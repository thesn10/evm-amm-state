//! Offline tests for Curve plain-pool auto-discovery (`MetaRegistry` + NG factories),
//! covering both the synchronous [`PoolDiscovery`] (`AdapterCache`) path and the
//! asynchronous [`discover_curve_pools`] (`Provider`) path.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use alloy_eips::BlockId;
use alloy_json_rpc::{RequestPacket, Response, ResponsePacket, ResponsePayload};
use alloy_primitives::{Address, Bytes, U256, address};
use alloy_provider::ProviderBuilder;
use alloy_rpc_client::RpcClient;
use alloy_sol_types::{SolCall, sol};
use alloy_transport::{TransportError, TransportErrorKind};
use evm_amm_state::adapters::curve::CurveAdapter;
use evm_amm_state::adapters::{
    AdapterCache, AdapterRegistry, CacheError, CallOutcome, CurveDiscoveryConfig,
    CurveFactorySource, CurveVariant, DiscoveryError, FactoryConfig, PoolDiscovery, PoolKey,
    PoolQuery, ProtocolId, ProtocolMetadata, SlotChange, StateDiff, StateUpdate, StateView,
    discover_curve_pools,
};
use serde_json::value::RawValue;
use tower::Service;

const META_REGISTRY: Address = address!("F98B45FA17DE75FB1aD0e7aFD971b0ca00e379fC");
const NG_FACTORY: Address = address!("6A8cbed756304B167629E2698967cA53cB4298f6");
const TRICRYPTO_FACTORY: Address = address!("0c0e5f2fF0ff18a3be9b835635039256dC4B4963");

const TOKEN_A: Address = address!("98a878b1cd98131b271883b390f68d2c90674665"); // apxUSD
const TOKEN_B: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC
const TOKEN_C: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7"); // USDT

const STABLE_POOL: Address = address!("e1b96555bbeca40e583bbb41a11c68ca4706a414");
const CRYPTO_V2_POOL: Address = address!("d51a44d3fae010294c616388b506acda1bfaae46");
const CRYPTO_NG_POOL: Address = address!("7f86bf177dd4f3494b841a37e810a34dd56c829b");
const META_POOL: Address = address!("1111111111111111111111111111111111111111");
const DEAD_POOL: Address = address!("2222222222222222222222222222222222222222");
const FACTORY_ONLY_POOL: Address = address!("3333333333333333333333333333333333333333");

sol! {
    function find_pools_for_coins(address _from, address _to) external view returns (address[] memory);
    function find_pool_for_coins(address _from, address _to, uint256 i) external view returns (address);
    function get_coins(address _pool) external view returns (address[8] memory);
    function get_n_coins(address _pool) external view returns (uint256);
    function is_meta(address _pool) external view returns (bool);
    function coins(uint256 i) external view returns (address);
    function factory() external view returns (address);
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);

    interface ICryptoGetDy {
        function get_dy(uint256 i, uint256 j, uint256 dx) external view returns (uint256);
    }
}

#[derive(Clone)]
enum MockReply {
    Success(Bytes),
    Revert,
    TransportError,
}

#[derive(Default)]
struct MockCallBook {
    replies: HashMap<(Address, Bytes), MockReply>,
}

impl MockCallBook {
    fn on_success(&mut self, to: Address, calldata: Vec<u8>, output: Vec<u8>) {
        self.replies.insert(
            (to, Bytes::from(calldata)),
            MockReply::Success(Bytes::from(output)),
        );
    }

    fn on_revert(&mut self, to: Address, calldata: Vec<u8>) {
        self.replies
            .insert((to, Bytes::from(calldata)), MockReply::Revert);
    }

    fn on_transport_error(&mut self, to: Address, calldata: Vec<u8>) {
        self.replies
            .insert((to, Bytes::from(calldata)), MockReply::TransportError);
    }

    fn lookup(&self, to: Address, calldata: &Bytes) -> MockReply {
        self.replies
            .get(&(to, calldata.clone()))
            .cloned()
            .unwrap_or(MockReply::Revert)
    }
}

struct MockCache {
    book: MockCallBook,
}

impl StateView for MockCache {
    fn storage(&self, _address: Address, _slot: U256) -> Option<U256> {
        None
    }
}

impl AdapterCache for MockCache {
    fn read_storage_slot(&mut self, _address: Address, _slot: U256) -> Result<U256, CacheError> {
        Ok(U256::ZERO)
    }

    fn cached_storage(&self, _address: Address, _slot: U256) -> Option<U256> {
        None
    }

    fn apply_updates(&mut self, _updates: &[StateUpdate]) -> StateDiff {
        StateDiff::default()
    }

    fn verify_slots(&mut self, _slots: &[(Address, U256)]) -> Result<Vec<SlotChange>, CacheError> {
        Ok(Vec::new())
    }

    fn purge_storage(&mut self, _address: Address) -> StateDiff {
        StateDiff::default()
    }

    fn purge_slots(&mut self, _address: Address, _slots: &[U256]) -> StateDiff {
        StateDiff::default()
    }

    fn call_raw(
        &mut self,
        _from: Address,
        to: Address,
        calldata: Bytes,
        _commit: bool,
    ) -> Result<CallOutcome, CacheError> {
        match self.book.lookup(to, &calldata) {
            MockReply::Success(output) => Ok(CallOutcome::Success {
                output,
                gas_used: 0,
            }),
            MockReply::Revert => Ok(CallOutcome::Revert {
                output: Bytes::new(),
                gas_used: 0,
            }),
            MockReply::TransportError => Err(CacheError::Backend(Box::new(std::io::Error::other(
                "transport down",
            )))),
        }
    }
}

#[derive(Clone)]
struct MockRpcService {
    book: Arc<MockCallBook>,
}

impl Service<RequestPacket> for MockRpcService {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let book = Arc::clone(&self.book);
        Box::pin(async move {
            let single = match req {
                RequestPacket::Single(single) => single,
                RequestPacket::Batch(_) => {
                    return Err(TransportErrorKind::custom_str("unexpected batch"));
                }
            };
            let id = single.id().clone();
            let params: serde_json::Value =
                serde_json::from_str(single.params().map(|p| p.get()).unwrap_or("[]"))
                    .map_err(TransportErrorKind::custom)?;
            let tx = params
                .get(0)
                .ok_or_else(|| TransportErrorKind::custom_str("missing tx"))?;
            let to: Address = tx["to"]
                .as_str()
                .ok_or_else(|| TransportErrorKind::custom_str("missing to"))?
                .parse()
                .map_err(TransportErrorKind::custom)?;
            let data_hex = tx
                .get("input")
                .or_else(|| tx.get("data"))
                .and_then(|v| v.as_str())
                .unwrap_or("0x");
            let calldata: Bytes = data_hex.parse().map_err(TransportErrorKind::custom)?;

            let response = match book.lookup(to, &calldata) {
                MockReply::Success(output) => {
                    let raw = RawValue::from_string(format!("\"0x{}\"", hex_encode(&output)))
                        .map_err(TransportErrorKind::custom)?;
                    Response {
                        id,
                        payload: ResponsePayload::Success(raw),
                    }
                }
                MockReply::Revert => Response {
                    id,
                    payload: ResponsePayload::Failure(alloy_json_rpc::ErrorPayload {
                        code: 3,
                        message: "execution reverted".into(),
                        data: None,
                    }),
                },
                MockReply::TransportError => {
                    return Err(TransportErrorKind::custom_str("offline store miss"));
                }
            };
            Ok(ResponsePacket::Single(response))
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixed_8(coins: &[Address]) -> [Address; 8] {
    let mut out = [Address::ZERO; 8];
    for (slot, &coin) in out.iter_mut().zip(coins.iter()) {
        *slot = coin;
    }
    out
}

fn populate_fixture_book() -> MockCallBook {
    let mut book = MockCallBook::default();
    let probe_dx = U256::from(1_000_000u64);

    // Pair (TOKEN_A, TOKEN_B) sorted order is (TOKEN_A, TOKEN_B) since 0x98.. < 0xA0..
    book.on_success(
        META_REGISTRY,
        find_pools_for_coinsCall {
            _from: TOKEN_A,
            _to: TOKEN_B,
        }
        .abi_encode(),
        find_pools_for_coinsCall::abi_encode_returns(&vec![
            STABLE_POOL,
            META_POOL,
            DEAD_POOL,
            CRYPTO_V2_POOL,
            CRYPTO_NG_POOL,
        ]),
    );

    // StableSwap plain pool
    book.on_success(
        META_REGISTRY,
        is_metaCall { _pool: STABLE_POOL }.abi_encode(),
        is_metaCall::abi_encode_returns(&false),
    );
    book.on_success(
        META_REGISTRY,
        get_coinsCall { _pool: STABLE_POOL }.abi_encode(),
        get_coinsCall::abi_encode_returns(&fixed_8(&[TOKEN_A, TOKEN_B])),
    );
    book.on_success(
        META_REGISTRY,
        get_n_coinsCall { _pool: STABLE_POOL }.abi_encode(),
        get_n_coinsCall::abi_encode_returns(&U256::from(2)),
    );
    book.on_success(
        STABLE_POOL,
        get_dyCall {
            i: 0,
            j: 1,
            dx: probe_dx,
        }
        .abi_encode(),
        get_dyCall::abi_encode_returns(&U256::from(999_000u64)),
    );

    // Metapool: filtered out
    book.on_success(
        META_REGISTRY,
        is_metaCall { _pool: META_POOL }.abi_encode(),
        is_metaCall::abi_encode_returns(&true),
    );

    // Dead/empty pool: both get_dy revert -> filtered out
    book.on_success(
        META_REGISTRY,
        is_metaCall { _pool: DEAD_POOL }.abi_encode(),
        is_metaCall::abi_encode_returns(&false),
    );
    book.on_success(
        META_REGISTRY,
        get_coinsCall { _pool: DEAD_POOL }.abi_encode(),
        get_coinsCall::abi_encode_returns(&fixed_8(&[TOKEN_A, TOKEN_B])),
    );
    book.on_success(
        META_REGISTRY,
        get_n_coinsCall { _pool: DEAD_POOL }.abi_encode(),
        get_n_coinsCall::abi_encode_returns(&U256::from(2)),
    );
    book.on_revert(
        DEAD_POOL,
        get_dyCall {
            i: 0,
            j: 1,
            dx: probe_dx,
        }
        .abi_encode(),
    );
    book.on_revert(
        DEAD_POOL,
        ICryptoGetDy::get_dyCall {
            i: U256::ZERO,
            j: U256::from(1),
            dx: probe_dx,
        }
        .abi_encode(),
    );

    // CryptoSwap v2 pool: old Vyper returns empty `0x` on unknown selectors (int128 get_dy, factory)
    book.on_success(
        META_REGISTRY,
        is_metaCall {
            _pool: CRYPTO_V2_POOL,
        }
        .abi_encode(),
        is_metaCall::abi_encode_returns(&false),
    );
    book.on_success(
        META_REGISTRY,
        get_coinsCall {
            _pool: CRYPTO_V2_POOL,
        }
        .abi_encode(),
        get_coinsCall::abi_encode_returns(&fixed_8(&[TOKEN_A, TOKEN_B, TOKEN_C])),
    );
    book.on_success(
        META_REGISTRY,
        get_n_coinsCall {
            _pool: CRYPTO_V2_POOL,
        }
        .abi_encode(),
        get_n_coinsCall::abi_encode_returns(&U256::from(3)),
    );
    book.on_success(
        CRYPTO_V2_POOL,
        get_dyCall {
            i: 0,
            j: 1,
            dx: probe_dx,
        }
        .abi_encode(),
        Vec::new(), // empty bytes, NOT 32 bytes!
    );
    book.on_success(
        CRYPTO_V2_POOL,
        ICryptoGetDy::get_dyCall {
            i: U256::ZERO,
            j: U256::from(1),
            dx: probe_dx,
        }
        .abi_encode(),
        ICryptoGetDy::get_dyCall::abi_encode_returns(&U256::from(500u64)),
    );
    book.on_success(CRYPTO_V2_POOL, factoryCall {}.abi_encode(), Vec::new());

    // CryptoSwapNG pool: int128 reverts, uint256 succeeds, factory() returns non-zero
    book.on_success(
        META_REGISTRY,
        is_metaCall {
            _pool: CRYPTO_NG_POOL,
        }
        .abi_encode(),
        is_metaCall::abi_encode_returns(&false),
    );
    book.on_success(
        META_REGISTRY,
        get_coinsCall {
            _pool: CRYPTO_NG_POOL,
        }
        .abi_encode(),
        get_coinsCall::abi_encode_returns(&fixed_8(&[TOKEN_B, TOKEN_A, TOKEN_C])),
    );
    book.on_success(
        META_REGISTRY,
        get_n_coinsCall {
            _pool: CRYPTO_NG_POOL,
        }
        .abi_encode(),
        get_n_coinsCall::abi_encode_returns(&U256::from(3)),
    );
    book.on_success(
        CRYPTO_NG_POOL,
        ICryptoGetDy::get_dyCall {
            i: U256::ZERO,
            j: U256::from(1),
            dx: probe_dx,
        }
        .abi_encode(),
        ICryptoGetDy::get_dyCall::abi_encode_returns(&U256::from(777u64)),
    );
    book.on_success(
        CRYPTO_NG_POOL,
        factoryCall {}.abi_encode(),
        factoryCall::abi_encode_returns(&TRICRYPTO_FACTORY),
    );

    // NG Factory returns STABLE_POOL (duplicate of MetaRegistry) at i=0, FACTORY_ONLY_POOL at i=1, zero at i=2
    book.on_success(
        NG_FACTORY,
        find_pool_for_coinsCall {
            _from: TOKEN_A,
            _to: TOKEN_B,
            i: U256::ZERO,
        }
        .abi_encode(),
        find_pool_for_coinsCall::abi_encode_returns(&STABLE_POOL),
    );
    book.on_success(
        NG_FACTORY,
        find_pool_for_coinsCall {
            _from: TOKEN_A,
            _to: TOKEN_B,
            i: U256::from(1),
        }
        .abi_encode(),
        find_pool_for_coinsCall::abi_encode_returns(&FACTORY_ONLY_POOL),
    );
    book.on_success(
        NG_FACTORY,
        find_pool_for_coinsCall {
            _from: TOKEN_A,
            _to: TOKEN_B,
            i: U256::from(2),
        }
        .abi_encode(),
        find_pool_for_coinsCall::abi_encode_returns(&Address::ZERO),
    );
    book.on_success(
        NG_FACTORY,
        is_metaCall {
            _pool: FACTORY_ONLY_POOL,
        }
        .abi_encode(),
        is_metaCall::abi_encode_returns(&false),
    );
    book.on_success(
        FACTORY_ONLY_POOL,
        coinsCall { i: U256::ZERO }.abi_encode(),
        coinsCall::abi_encode_returns(&TOKEN_B),
    );
    book.on_success(
        FACTORY_ONLY_POOL,
        coinsCall { i: U256::from(1) }.abi_encode(),
        coinsCall::abi_encode_returns(&TOKEN_A),
    );
    book.on_revert(
        FACTORY_ONLY_POOL,
        coinsCall { i: U256::from(2) }.abi_encode(),
    );
    book.on_success(
        FACTORY_ONLY_POOL,
        get_dyCall {
            i: 0,
            j: 1,
            dx: probe_dx,
        }
        .abi_encode(),
        get_dyCall::abi_encode_returns(&U256::from(1_000_000u64)),
    );

    book
}

fn test_config() -> CurveDiscoveryConfig {
    CurveDiscoveryConfig::ethereum_meta_registry()
        .with_factory(CurveFactorySource::new(NG_FACTORY).with_variant(CurveVariant::StableSwap))
}

fn assert_expected_pools(found: &[evm_amm_state::adapters::DiscoveredPool]) {
    assert_eq!(found.len(), 4, "expected 4 live plain pools, got {found:?}");

    let by_addr: HashMap<Address, (&[Address], CurveVariant)> = found
        .iter()
        .map(|pool| {
            let addr = pool.key.address().expect("curve pool address");
            let ProtocolMetadata::Curve(meta) = &pool.registration.metadata else {
                panic!("expected Curve metadata for {addr}");
            };
            assert_eq!(pool.key, PoolKey::Curve(addr));
            assert_eq!(pool.registration.state_addresses, vec![addr]);
            (addr, (meta.coins.as_slice(), meta.variant))
        })
        .collect();

    assert_eq!(
        by_addr.get(&STABLE_POOL),
        Some(&([TOKEN_A, TOKEN_B].as_slice(), CurveVariant::StableSwap))
    );
    assert_eq!(
        by_addr.get(&CRYPTO_V2_POOL),
        Some(&(
            [TOKEN_A, TOKEN_B, TOKEN_C].as_slice(),
            CurveVariant::CryptoSwap
        ))
    );
    assert_eq!(
        by_addr.get(&CRYPTO_NG_POOL),
        Some(&(
            [TOKEN_B, TOKEN_A, TOKEN_C].as_slice(),
            CurveVariant::CryptoSwapNG
        ))
    );
    assert_eq!(
        by_addr.get(&FACTORY_ONLY_POOL),
        Some(&([TOKEN_B, TOKEN_A].as_slice(), CurveVariant::StableSwap))
    );
    assert!(
        !by_addr.contains_key(&META_POOL),
        "metapool must be filtered"
    );
    assert!(
        !by_addr.contains_key(&DEAD_POOL),
        "dead pool must be filtered"
    );
}

#[test]
fn pool_discovery_sync_finds_and_classifies_curve_pools() {
    let mut registry = AdapterRegistry::new();
    registry
        .register_adapter(Arc::new(CurveAdapter::default()))
        .expect("register curve adapter");
    let discovery = PoolDiscovery::for_registry(
        &registry,
        FactoryConfig::default().with_curve(test_config()),
    );

    let mut cache = MockCache {
        book: populate_fixture_book(),
    };
    let found = discovery
        .find(
            &mut cache,
            PoolQuery::pair(TOKEN_B, TOKEN_A).on(ProtocolId::Curve),
        )
        .expect("curve discovery");
    assert_expected_pools(&found);
}

#[tokio::test]
async fn async_discover_curve_pools_finds_and_classifies_pools() {
    let service = MockRpcService {
        book: Arc::new(populate_fixture_book()),
    };
    let client = RpcClient::new(service, true);
    let provider = ProviderBuilder::new().connect_client(client);

    let found = discover_curve_pools(
        &provider,
        BlockId::number(25_238_039),
        &test_config(),
        &PoolQuery::pair(TOKEN_B, TOKEN_A),
    )
    .await
    .expect("async curve discovery");
    assert_expected_pools(&found);

    // Query scoped to another protocol is a clean no-op.
    let other = discover_curve_pools(
        &provider,
        BlockId::number(25_238_039),
        &test_config(),
        &PoolQuery::pair(TOKEN_B, TOKEN_A).on(ProtocolId::UniswapV3),
    )
    .await
    .expect("other protocol");
    assert!(other.is_empty());
}

#[tokio::test]
async fn async_discover_curve_pools_propagates_transport_errors() {
    let mut book = MockCallBook::default();
    book.on_transport_error(
        META_REGISTRY,
        find_pools_for_coinsCall {
            _from: TOKEN_A,
            _to: TOKEN_B,
        }
        .abi_encode(),
    );
    let service = MockRpcService {
        book: Arc::new(book),
    };
    let client = RpcClient::new(service, true);
    let provider = ProviderBuilder::new().connect_client(client);

    let err = discover_curve_pools(
        &provider,
        BlockId::number(25_238_039),
        &CurveDiscoveryConfig::ethereum_meta_registry(),
        &PoolQuery::pair(TOKEN_A, TOKEN_B),
    )
    .await
    .expect_err("transport error must propagate");
    assert!(matches!(err, DiscoveryError::Factory(_)));
}

#[tokio::test]
async fn max_pools_per_pair_bounds_meta_registry_live_plain_pools() {
    let service = MockRpcService {
        book: Arc::new(populate_fixture_book()),
    };
    let client = RpcClient::new(service, true);
    let provider = ProviderBuilder::new().connect_client(client);

    // Fixture has 3 live plain pools (STABLE_POOL, CRYPTO_V2_POOL, CRYPTO_NG_POOL) plus
    // META_POOL and DEAD_POOL in MetaRegistry; cap at 2 live plain pools.
    let cfg = CurveDiscoveryConfig::ethereum_meta_registry().with_max_pools_per_pair(2);
    let found = discover_curve_pools(
        &provider,
        BlockId::number(25_238_039),
        &cfg,
        &PoolQuery::pair(TOKEN_A, TOKEN_B),
    )
    .await
    .expect("capped discovery");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].key, PoolKey::Curve(STABLE_POOL));
    assert_eq!(found[1].key, PoolKey::Curve(CRYPTO_V2_POOL));
}
