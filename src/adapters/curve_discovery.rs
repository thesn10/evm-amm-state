//! On-chain Curve plain-pool auto-discovery via `MetaRegistry` and NG factories.
//!
//! Curve pools cannot be resolved from a single derived factory storage slot
//! because `MetaRegistry` delegates across multiple registry handlers and NG
//! factories expose view-call pair indices. This module provides two entry
//! points that share the same ABI encoding, filtering, and variant detection:
//!
//! - [`discover_curve_pools`] — async, provider-backed (`eth_call` at an exact
//!   [`BlockId`]). Works against live RPC nodes as well as pinned/cached
//!   historical providers.
//! - [`CurvePoolFactory`] — synchronous [`PoolFactory`] implementation wired
//!   into [`FactoryConfig::curve`](super::FactoryConfig) and
//!   [`CurveAdapter::pool_factories`](super::curve::CurveAdapter), resolving
//!   through [`AdapterCache::call_raw`].
//!
//! Metapools (`is_meta(pool) == true`) and uninitialized/empty pools whose
//! `get_dy` reverts for both `int128` and `uint256` ABIs are filtered out,
//! matching [`CurveAdapter`](super::curve::CurveAdapter)'s plain-pool scope.

use std::collections::HashSet;

use crate::alloy_eips::BlockId;
use crate::alloy_network::Network;
use crate::alloy_provider::Provider;
use crate::alloy_rpc_types_eth::TransactionRequest;
use alloy_primitives::{Address, Bytes, Log, U256, address};
use alloy_sol_types::SolCall;

use super::factory::{
    CreationLogContext, DiscoveredPool, DiscoveryError, DiscoverySource, PoolFactory, PoolQuery,
};
use super::sim::{CurveCryptoSwap, get_dyCall};
use super::{
    AdapterCache, CurveMetadata, CurveVariant, EventSource, PoolKey, PoolRegistration, ProtocolId,
    ProtocolMetadata,
};

/// Canonical Curve `MetaRegistry` deployment on Ethereum mainnet.
pub const ETHEREUM_CURVE_META_REGISTRY: Address =
    address!("F98B45FA17DE75FB1aD0e7aFD971b0ca00e379fC");

/// Default upper bound on pools enumerated per `(factory, pair)` via
/// `find_pool_for_coins(from, to, i)`.
const DEFAULT_MAX_POOLS_PER_PAIR: usize = 8;

/// Maximum number of coins probed on a Curve pool when falling back to
/// `pool.coins(i)`.
const MAX_CURVE_COINS: usize = 8;

/// Small non-zero input amount used to probe `get_dy(0, 1, dx)` during variant
/// detection and liveness filtering.
const PROBE_DX: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

mod abi {
    use alloy_sol_types::sol;

    sol! {
        interface ICurveMetaRegistry {
            function find_pools_for_coins(address _from, address _to) external view returns (address[] memory);
            function get_coins(address _pool) external view returns (address[8] memory);
            function get_n_coins(address _pool) external view returns (uint256);
            function is_meta(address _pool) external view returns (bool);
        }

        interface ICurveFactory {
            function find_pool_for_coins(address _from, address _to, uint256 i) external view returns (address);
            function is_meta(address _pool) external view returns (bool);
        }

        interface ICurvePoolProbe {
            function coins(uint256 i) external view returns (address);
            function factory() external view returns (address);
        }
    }
}

use abi::{ICurveFactory, ICurveMetaRegistry, ICurvePoolProbe};

/// One Curve factory contract queried via `find_pool_for_coins(from, to, i)`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurveFactorySource {
    /// Address of the Curve factory contract.
    pub address: Address,
    /// Optional known [`CurveVariant`] for pools deployed by this factory.
    ///
    /// When `None`, the variant is probed on-chain via `get_dy` and `factory()`.
    pub variant: Option<CurveVariant>,
}

impl CurveFactorySource {
    /// Create a factory source whose pool variants are auto-detected.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            variant: None,
        }
    }

    /// Pin the [`CurveVariant`] emitted for pools discovered from this factory.
    pub fn with_variant(mut self, variant: CurveVariant) -> Self {
        self.variant = Some(variant);
        self
    }
}

/// Configuration for Curve plain-pool auto-discovery.
///
/// Defaults are empty (opt-in); use [`CurveDiscoveryConfig::ethereum_meta_registry`]
/// or the builder methods to enable `MetaRegistry` and/or factory sources.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurveDiscoveryConfig {
    /// Optional Curve `MetaRegistry` address (Ethereum mainnet).
    pub meta_registry: Option<Address>,
    /// Curve factories queried via `find_pool_for_coins(from, to, i)` (L2s or
    /// additional registries).
    pub factories: Vec<CurveFactorySource>,
    /// Maximum number of pools to enumerate per `(factory, pair)`.
    pub max_pools_per_pair: usize,
}

impl Default for CurveDiscoveryConfig {
    fn default() -> Self {
        Self {
            meta_registry: None,
            factories: Vec::new(),
            max_pools_per_pair: DEFAULT_MAX_POOLS_PER_PAIR,
        }
    }
}

impl CurveDiscoveryConfig {
    /// Preset targeting Ethereum mainnet's canonical Curve `MetaRegistry`.
    pub fn ethereum_meta_registry() -> Self {
        Self::default().with_meta_registry(ETHEREUM_CURVE_META_REGISTRY)
    }

    /// Configure the Curve `MetaRegistry` contract address.
    pub fn with_meta_registry(mut self, meta_registry: Address) -> Self {
        self.meta_registry = Some(meta_registry);
        self
    }

    /// Append one Curve factory source (`find_pool_for_coins(from, to, i)`).
    pub fn with_factory(mut self, factory: CurveFactorySource) -> Self {
        self.factories.push(factory);
        self
    }

    /// Append multiple Curve factory sources.
    pub fn with_factories(
        mut self,
        factories: impl IntoIterator<Item = CurveFactorySource>,
    ) -> Self {
        self.factories.extend(factories);
        self
    }

    /// Override the maximum number of pools enumerated per `(factory, pair)`.
    pub fn with_max_pools_per_pair(mut self, limit: usize) -> Self {
        self.max_pools_per_pair = limit;
        self
    }

    /// Returns `true` when neither a `MetaRegistry` nor any factory is configured.
    pub fn is_empty(&self) -> bool {
        self.meta_registry.is_none() && self.factories.is_empty()
    }
}

/// Synchronous [`PoolFactory`] backed by [`CurveDiscoveryConfig`].
///
/// Resolves pairs through [`AdapterCache::call_raw`], so it works with
/// [`PoolDiscovery::find`](super::PoolDiscovery::find) and
/// [`PoolDiscovery::find_many`](super::PoolDiscovery::find_many). Because Curve
/// discovery requires view calls rather than derived storage slots, it does not
/// implement batched `candidate_reads`.
#[derive(Clone, Debug)]
pub struct CurvePoolFactory {
    config: CurveDiscoveryConfig,
}

impl CurvePoolFactory {
    /// Create a Curve discovery factory from `config`.
    pub fn new(config: CurveDiscoveryConfig) -> Self {
        Self { config }
    }

    /// Access the underlying [`CurveDiscoveryConfig`].
    pub fn config(&self) -> &CurveDiscoveryConfig {
        &self.config
    }
}

impl PoolFactory for CurvePoolFactory {
    fn protocol(&self) -> ProtocolId {
        ProtocolId::Curve
    }

    fn factory_address(&self) -> Address {
        self.config
            .meta_registry
            .or_else(|| self.config.factories.first().map(|f| f.address))
            .unwrap_or(Address::ZERO)
    }

    fn find_pools(
        &self,
        cache: &mut dyn AdapterCache,
        pair: (Address, Address),
    ) -> Result<Vec<DiscoveredPool>, DiscoveryError> {
        let mut seen = HashSet::new();
        let mut discovered = Vec::new();
        let (token_a, token_b) = pair;

        if let Some(meta_registry) = self.config.meta_registry {
            let candidates =
                cache_find_meta_registry_pools(cache, meta_registry, token_a, token_b)?;
            let mut found_for_pair = 0usize;
            for pool in candidates {
                if found_for_pair >= self.config.max_pools_per_pair {
                    break;
                }
                if !seen.insert(pool) {
                    continue;
                }
                if let Some(found) =
                    cache_inspect_pool(cache, pool, Some(meta_registry), None, None)?
                {
                    discovered.push(found);
                    found_for_pair += 1;
                }
            }
        }

        for factory in &self.config.factories {
            let candidates = cache_find_factory_pools(
                cache,
                factory.address,
                token_a,
                token_b,
                self.config.max_pools_per_pair,
            )?;
            for pool in candidates {
                if !seen.insert(pool) {
                    continue;
                }
                if let Some(found) =
                    cache_inspect_pool(cache, pool, None, Some(factory.address), factory.variant)?
                {
                    discovered.push(found);
                }
            }
        }

        Ok(discovered)
    }

    fn creation_sources(&self) -> Vec<EventSource> {
        Vec::new()
    }

    fn decode_creation(
        &self,
        _log: &Log,
        _context: CreationLogContext,
    ) -> Result<Option<DiscoveredPool>, DiscoveryError> {
        Ok(None)
    }
}

/// Discover Curve plain pools matching `query` via `eth_call`s at `block`.
///
/// Queries the configured `MetaRegistry` (`find_pools_for_coins`) and/or Curve
/// factories (`find_pool_for_coins`) for every pair in `query`, filters out
/// metapools and uninitialized/reverting pools, resolves each pool's coin
/// ordering and [`CurveVariant`], and returns de-duplicated [`DiscoveredPool`]
/// registrations.
///
/// Contract reverts on probe calls (such as `get_dy` with the wrong index ABI
/// or out-of-bounds `coins(i)`) are treated as negative probes; transport-level
/// provider errors are propagated as [`DiscoveryError::Factory`].
pub async fn discover_curve_pools<P, N>(
    provider: &P,
    block: BlockId,
    config: &CurveDiscoveryConfig,
    query: &PoolQuery,
) -> Result<Vec<DiscoveredPool>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    if query
        .protocol()
        .is_some_and(|protocol| protocol != ProtocolId::Curve)
    {
        return Ok(Vec::new());
    }

    let pairs = query.pairs_slice();
    if config.is_empty() || pairs.is_empty() {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut discovered = Vec::new();

    if let Some(meta_registry) = config.meta_registry {
        for &(token_a, token_b) in pairs {
            let candidates =
                rpc_find_meta_registry_pools(provider, block, meta_registry, token_a, token_b)
                    .await?;
            let mut found_for_pair = 0usize;
            for pool in candidates {
                if found_for_pair >= config.max_pools_per_pair {
                    break;
                }
                if !seen.insert(pool) {
                    continue;
                }
                if let Some(found) =
                    rpc_inspect_pool(provider, block, pool, Some(meta_registry), None, None).await?
                {
                    discovered.push(found);
                    found_for_pair += 1;
                }
            }
        }
    }

    for factory in &config.factories {
        for &(token_a, token_b) in pairs {
            let candidates = rpc_find_factory_pools(
                provider,
                block,
                factory.address,
                token_a,
                token_b,
                config.max_pools_per_pair,
            )
            .await?;
            for pool in candidates {
                if !seen.insert(pool) {
                    continue;
                }
                if let Some(found) = rpc_inspect_pool(
                    provider,
                    block,
                    pool,
                    None,
                    Some(factory.address),
                    factory.variant,
                )
                .await?
                {
                    discovered.push(found);
                }
            }
        }
    }

    Ok(discovered)
}

// ---------------------------------------------------------------------------
// Shared ABI encoding, decoding & registration assembly
// ---------------------------------------------------------------------------

fn encode_find_pools_for_coins(from: Address, to: Address) -> Bytes {
    ICurveMetaRegistry::find_pools_for_coinsCall {
        _from: from,
        _to: to,
    }
    .abi_encode()
    .into()
}

fn decode_find_pools_for_coins(raw: &[u8]) -> Vec<Address> {
    ICurveMetaRegistry::find_pools_for_coinsCall::abi_decode_returns(raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|addr| !addr.is_zero())
        .collect()
}

fn encode_find_pool_for_coins_at(from: Address, to: Address, index: usize) -> Bytes {
    ICurveFactory::find_pool_for_coinsCall {
        _from: from,
        _to: to,
        i: U256::from(index),
    }
    .abi_encode()
    .into()
}

fn decode_nonzero_address(raw: &[u8]) -> Option<Address> {
    if raw.len() != 32 {
        return None;
    }
    let addr = ICurvePoolProbe::factoryCall::abi_decode_returns(raw).ok()?;
    (!addr.is_zero()).then_some(addr)
}

fn encode_is_meta(pool: Address) -> Bytes {
    ICurveMetaRegistry::is_metaCall { _pool: pool }
        .abi_encode()
        .into()
}

fn decode_bool_return(raw: &[u8]) -> Option<bool> {
    if raw.len() != 32 {
        return None;
    }
    ICurveMetaRegistry::is_metaCall::abi_decode_returns(raw).ok()
}

fn encode_get_coins(pool: Address) -> Bytes {
    ICurveMetaRegistry::get_coinsCall { _pool: pool }
        .abi_encode()
        .into()
}

fn encode_get_n_coins(pool: Address) -> Bytes {
    ICurveMetaRegistry::get_n_coinsCall { _pool: pool }
        .abi_encode()
        .into()
}

fn decode_meta_registry_coins(coins_raw: &[u8], n_coins_raw: &[u8]) -> Option<Vec<Address>> {
    let coins_arr = ICurveMetaRegistry::get_coinsCall::abi_decode_returns(coins_raw).ok()?;
    let n_coins = decode_u256_return(n_coins_raw)?;
    let count = usize::try_from(n_coins).ok()?.min(coins_arr.len());
    let coins: Vec<Address> = coins_arr
        .into_iter()
        .take(count)
        .filter(|addr| !addr.is_zero())
        .collect();
    (coins.len() >= 2).then_some(coins)
}

fn encode_pool_coin(index: usize) -> Bytes {
    ICurvePoolProbe::coinsCall {
        i: U256::from(index),
    }
    .abi_encode()
    .into()
}

fn encode_probe_stable_get_dy() -> Bytes {
    get_dyCall {
        i: 0i128,
        j: 1i128,
        dx: PROBE_DX,
    }
    .abi_encode()
    .into()
}

fn encode_probe_crypto_get_dy() -> Bytes {
    CurveCryptoSwap::get_dyCall {
        i: U256::ZERO,
        j: U256::from(1),
        dx: PROBE_DX,
    }
    .abi_encode()
    .into()
}

fn encode_pool_factory() -> Bytes {
    ICurvePoolProbe::factoryCall {}.abi_encode().into()
}

/// Strictly decode a single `uint256` return word.
///
/// Older Vyper Curve contracts return empty bytes (`0x`) rather than reverting
/// when called with an unknown selector; requiring an exact 32-byte payload
/// avoids misclassifying those empty responses as a successful `get_dy`.
fn decode_u256_return(raw: &[u8]) -> Option<U256> {
    if raw.len() != 32 {
        return None;
    }
    get_dyCall::abi_decode_returns(raw).ok()
}

fn build_discovered_curve_pool(
    pool: Address,
    coins: Vec<Address>,
    variant: CurveVariant,
) -> Option<DiscoveredPool> {
    if pool.is_zero() || coins.len() < 2 {
        return None;
    }
    let mut unique = HashSet::with_capacity(coins.len());
    if coins
        .iter()
        .any(|coin| coin.is_zero() || !unique.insert(*coin))
    {
        return None;
    }

    let key = PoolKey::Curve(pool);
    let registration = PoolRegistration::new(key.clone())
        .with_state_address(pool)
        .with_metadata(ProtocolMetadata::Curve(
            CurveMetadata::default()
                .with_coins(coins)
                .with_variant(variant),
        ));

    Some(DiscoveredPool {
        key,
        registration,
        source: DiscoverySource::Query,
    })
}

// ---------------------------------------------------------------------------
// Provider-backed async helpers
// ---------------------------------------------------------------------------

async fn rpc_call_optional<P, N>(
    provider: &P,
    block: BlockId,
    to: Address,
    data: Bytes,
) -> Result<Option<Bytes>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    let tx = TransactionRequest::default().to(to).input(data.into());
    match provider.call(tx.into()).block(block).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.as_error_resp().is_some() => Ok(None),
        Err(err) => Err(DiscoveryError::Factory(Box::new(err))),
    }
}

async fn rpc_find_meta_registry_pools<P, N>(
    provider: &P,
    block: BlockId,
    meta_registry: Address,
    token_a: Address,
    token_b: Address,
) -> Result<Vec<Address>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    let Some(raw) = rpc_call_optional(
        provider,
        block,
        meta_registry,
        encode_find_pools_for_coins(token_a, token_b),
    )
    .await?
    else {
        return Ok(Vec::new());
    };
    Ok(decode_find_pools_for_coins(&raw))
}

async fn rpc_find_factory_pools<P, N>(
    provider: &P,
    block: BlockId,
    factory: Address,
    token_a: Address,
    token_b: Address,
    max_pools: usize,
) -> Result<Vec<Address>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    let mut pools = Vec::new();
    for index in 0..max_pools {
        let Some(raw) = rpc_call_optional(
            provider,
            block,
            factory,
            encode_find_pool_for_coins_at(token_a, token_b, index),
        )
        .await?
        else {
            break;
        };
        let Some(pool) = decode_nonzero_address(&raw) else {
            break;
        };
        pools.push(pool);
    }
    Ok(pools)
}

async fn rpc_inspect_pool<P, N>(
    provider: &P,
    block: BlockId,
    pool: Address,
    meta_registry: Option<Address>,
    factory: Option<Address>,
    variant_hint: Option<CurveVariant>,
) -> Result<Option<DiscoveredPool>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    // Skip metapools: CurveAdapter's restrict_to=[pool] cold-start only supports plain pools.
    if let Some(meta_checker) = meta_registry.or(factory)
        && let Some(raw) =
            rpc_call_optional(provider, block, meta_checker, encode_is_meta(pool)).await?
        && decode_bool_return(&raw) == Some(true)
    {
        return Ok(None);
    }

    let coins = rpc_resolve_coins(provider, block, pool, meta_registry).await?;
    if coins.len() < 2 {
        return Ok(None);
    }

    let Some(variant) = rpc_probe_variant(provider, block, pool, variant_hint).await? else {
        return Ok(None);
    };

    Ok(build_discovered_curve_pool(pool, coins, variant))
}

async fn rpc_resolve_coins<P, N>(
    provider: &P,
    block: BlockId,
    pool: Address,
    meta_registry: Option<Address>,
) -> Result<Vec<Address>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    if let Some(registry) = meta_registry {
        let coins_raw =
            rpc_call_optional(provider, block, registry, encode_get_coins(pool)).await?;
        let n_coins_raw =
            rpc_call_optional(provider, block, registry, encode_get_n_coins(pool)).await?;
        if let (Some(coins_raw), Some(n_coins_raw)) = (coins_raw, n_coins_raw)
            && let Some(coins) = decode_meta_registry_coins(&coins_raw, &n_coins_raw)
        {
            return Ok(coins);
        }
    }

    let mut coins = Vec::new();
    for index in 0..MAX_CURVE_COINS {
        let Some(raw) = rpc_call_optional(provider, block, pool, encode_pool_coin(index)).await?
        else {
            break;
        };
        let Some(coin) = decode_nonzero_address(&raw) else {
            break;
        };
        coins.push(coin);
    }
    Ok(coins)
}

async fn rpc_probe_variant<P, N>(
    provider: &P,
    block: BlockId,
    pool: Address,
    variant_hint: Option<CurveVariant>,
) -> Result<Option<CurveVariant>, DiscoveryError>
where
    P: Provider<N>,
    N: Network,
    N::TransactionRequest: From<TransactionRequest>,
{
    if let Some(hint) = variant_hint {
        let probe = match hint {
            CurveVariant::StableSwap => encode_probe_stable_get_dy(),
            CurveVariant::CryptoSwap | CurveVariant::CryptoSwapNG => encode_probe_crypto_get_dy(),
        };
        let ok = rpc_call_optional(provider, block, pool, probe)
            .await?
            .and_then(|raw| decode_u256_return(&raw))
            .is_some();
        return Ok(ok.then_some(hint));
    }

    if rpc_call_optional(provider, block, pool, encode_probe_stable_get_dy())
        .await?
        .and_then(|raw| decode_u256_return(&raw))
        .is_some()
    {
        return Ok(Some(CurveVariant::StableSwap));
    }

    if rpc_call_optional(provider, block, pool, encode_probe_crypto_get_dy())
        .await?
        .and_then(|raw| decode_u256_return(&raw))
        .is_some()
    {
        let is_ng = rpc_call_optional(provider, block, pool, encode_pool_factory())
            .await?
            .and_then(|raw| decode_nonzero_address(&raw))
            .is_some();
        return Ok(Some(if is_ng {
            CurveVariant::CryptoSwapNG
        } else {
            CurveVariant::CryptoSwap
        }));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Cache-backed synchronous helpers (for PoolFactory::find_pools)
// ---------------------------------------------------------------------------

fn cache_call_optional(
    cache: &mut dyn AdapterCache,
    to: Address,
    data: Bytes,
) -> Result<Option<Bytes>, DiscoveryError> {
    let outcome = cache.call_raw(Address::ZERO, to, data, false)?;
    Ok(match outcome {
        super::CallOutcome::Success { output, .. } => Some(output),
        _ => None,
    })
}

fn cache_find_meta_registry_pools(
    cache: &mut dyn AdapterCache,
    meta_registry: Address,
    token_a: Address,
    token_b: Address,
) -> Result<Vec<Address>, DiscoveryError> {
    let Some(raw) = cache_call_optional(
        cache,
        meta_registry,
        encode_find_pools_for_coins(token_a, token_b),
    )?
    else {
        return Ok(Vec::new());
    };
    Ok(decode_find_pools_for_coins(&raw))
}

fn cache_find_factory_pools(
    cache: &mut dyn AdapterCache,
    factory: Address,
    token_a: Address,
    token_b: Address,
    max_pools: usize,
) -> Result<Vec<Address>, DiscoveryError> {
    let mut pools = Vec::new();
    for index in 0..max_pools {
        let Some(raw) = cache_call_optional(
            cache,
            factory,
            encode_find_pool_for_coins_at(token_a, token_b, index),
        )?
        else {
            break;
        };
        let Some(pool) = decode_nonzero_address(&raw) else {
            break;
        };
        pools.push(pool);
    }
    Ok(pools)
}

fn cache_inspect_pool(
    cache: &mut dyn AdapterCache,
    pool: Address,
    meta_registry: Option<Address>,
    factory: Option<Address>,
    variant_hint: Option<CurveVariant>,
) -> Result<Option<DiscoveredPool>, DiscoveryError> {
    if let Some(meta_checker) = meta_registry.or(factory)
        && let Some(raw) = cache_call_optional(cache, meta_checker, encode_is_meta(pool))?
        && decode_bool_return(&raw) == Some(true)
    {
        return Ok(None);
    }

    let coins = cache_resolve_coins(cache, pool, meta_registry)?;
    if coins.len() < 2 {
        return Ok(None);
    }

    let Some(variant) = cache_probe_variant(cache, pool, variant_hint)? else {
        return Ok(None);
    };

    Ok(build_discovered_curve_pool(pool, coins, variant))
}

fn cache_resolve_coins(
    cache: &mut dyn AdapterCache,
    pool: Address,
    meta_registry: Option<Address>,
) -> Result<Vec<Address>, DiscoveryError> {
    if let Some(registry) = meta_registry {
        let coins_raw = cache_call_optional(cache, registry, encode_get_coins(pool))?;
        let n_coins_raw = cache_call_optional(cache, registry, encode_get_n_coins(pool))?;
        if let (Some(coins_raw), Some(n_coins_raw)) = (coins_raw, n_coins_raw)
            && let Some(coins) = decode_meta_registry_coins(&coins_raw, &n_coins_raw)
        {
            return Ok(coins);
        }
    }

    let mut coins = Vec::new();
    for index in 0..MAX_CURVE_COINS {
        let Some(raw) = cache_call_optional(cache, pool, encode_pool_coin(index))? else {
            break;
        };
        let Some(coin) = decode_nonzero_address(&raw) else {
            break;
        };
        coins.push(coin);
    }
    Ok(coins)
}

fn cache_probe_variant(
    cache: &mut dyn AdapterCache,
    pool: Address,
    variant_hint: Option<CurveVariant>,
) -> Result<Option<CurveVariant>, DiscoveryError> {
    if let Some(hint) = variant_hint {
        let probe = match hint {
            CurveVariant::StableSwap => encode_probe_stable_get_dy(),
            CurveVariant::CryptoSwap | CurveVariant::CryptoSwapNG => encode_probe_crypto_get_dy(),
        };
        let ok = cache_call_optional(cache, pool, probe)?
            .and_then(|raw| decode_u256_return(&raw))
            .is_some();
        return Ok(ok.then_some(hint));
    }

    if cache_call_optional(cache, pool, encode_probe_stable_get_dy())?
        .and_then(|raw| decode_u256_return(&raw))
        .is_some()
    {
        return Ok(Some(CurveVariant::StableSwap));
    }

    if cache_call_optional(cache, pool, encode_probe_crypto_get_dy())?
        .and_then(|raw| decode_u256_return(&raw))
        .is_some()
    {
        let is_ng = cache_call_optional(cache, pool, encode_pool_factory())?
            .and_then(|raw| decode_nonzero_address(&raw))
            .is_some();
        return Ok(Some(if is_ng {
            CurveVariant::CryptoSwapNG
        } else {
            CurveVariant::CryptoSwap
        }));
    }

    Ok(None)
}
