use core::fmt;
use std::{collections::HashMap, sync::Mutex};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{Clock, DpopError, DpopNonce, DpopPortError, ReplayKey, ReplayStatus, ReplayStore};

const MAX_NONCE_CONTEXT_BYTES: usize = 2_048;
const GENERATED_NONCE_BYTES: usize = 16;

/// Deployment scope advertised by Keylix reference state stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateStoreTopology {
    /// State and atomicity exist only inside one process.
    SingleProcess,
}

/// Consistency guarantee advertised by Keylix reference state stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateStoreConsistency {
    /// Operations are serialized atomically by one process-local mutex.
    ProcessLocalAtomic,
}

/// Security-relevant metadata for a bounded reference state store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateStoreMetadata {
    topology: StateStoreTopology,
    consistency: StateStoreConsistency,
    capacity: usize,
}

impl StateStoreMetadata {
    /// Returns the topology over which this store's guarantees hold.
    #[must_use]
    pub const fn topology(&self) -> StateStoreTopology {
        self.topology
    }

    /// Returns the consistency/atomicity guarantee of this store.
    #[must_use]
    pub const fn consistency(&self) -> StateStoreConsistency {
        self.consistency
    }

    /// Returns the configured maximum number of active entries.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Bounded, process-local atomic replay store for tests and single-instance use.
///
/// Active replay records are never evicted to make room. When capacity is full
/// after expired records are removed, insertion fails closed through
/// [`DpopPortError`]. Multi-instance deployments must supply a shared
/// [`ReplayStore`] implementation whose atomicity covers all relevant instances.
pub struct InMemoryReplayStore<C> {
    clock: C,
    capacity: usize,
    entries: Mutex<HashMap<ReplayKey, i64>>,
}

impl<C> InMemoryReplayStore<C> {
    /// Creates a bounded single-process replay store.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidPolicy`] when `capacity` is zero.
    pub fn new(clock: C, capacity: usize) -> Result<Self, DpopError> {
        if capacity == 0 {
            return Err(DpopError::InvalidPolicy);
        }
        Ok(Self {
            clock,
            capacity,
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Returns explicit topology, consistency, and capacity metadata.
    #[must_use]
    pub const fn metadata(&self) -> StateStoreMetadata {
        StateStoreMetadata {
            topology: StateStoreTopology::SingleProcess,
            consistency: StateStoreConsistency::ProcessLocalAtomic,
            capacity: self.capacity,
        }
    }
}

impl<C> fmt::Debug for InMemoryReplayStore<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryReplayStore")
            .field("metadata", &self.metadata())
            .field("entries", &"[redacted replay state]")
            .finish()
    }
}

impl<C> ReplayStore for InMemoryReplayStore<C>
where
    C: Clock,
{
    fn check_and_record(
        &self,
        key: &ReplayKey,
        expires_at_unix: i64,
    ) -> Result<ReplayStatus, DpopPortError> {
        let now = self.clock.unix_seconds()?;
        if expires_at_unix < now {
            return Err(DpopPortError);
        }

        let mut entries = self.entries.lock().map_err(|_| DpopPortError)?;
        // Freshness accepts the exact `iat + max_age` boundary, so a replay
        // record remains active through that second and expires only afterward.
        entries.retain(|_, expiry| *expiry >= now);

        if entries.contains_key(key) {
            return Ok(ReplayStatus::Replay);
        }
        if entries.len() >= self.capacity {
            return Err(DpopPortError);
        }

        entries.insert(*key, expires_at_unix);
        Ok(ReplayStatus::Fresh)
    }
}

/// Distinguishes authorization-server and resource-server nonce namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NonceNamespace {
    /// OAuth authorization-server nonce state.
    AuthorizationServer,
    /// Protected resource-server nonce state.
    ResourceServer,
}

/// Opaque, bounded nonce state key for one issuing server context.
///
/// The integration layer is responsible for supplying a stable canonical
/// server identifier. Keylix additionally namespaces it by AS vs RS so nonce
/// state can never cross those protocol roles accidentally.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NonceContext {
    namespace: NonceNamespace,
    server_id: String,
}

impl NonceContext {
    /// Creates a scoped nonce context.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidPolicy`] for an empty, oversized, or
    /// control-character-bearing server identifier.
    pub fn new(namespace: NonceNamespace, server_id: impl Into<String>) -> Result<Self, DpopError> {
        let server_id = server_id.into();
        if server_id.is_empty()
            || server_id.len() > MAX_NONCE_CONTEXT_BYTES
            || server_id.chars().any(char::is_control)
        {
            return Err(DpopError::InvalidPolicy);
        }
        Ok(Self {
            namespace,
            server_id,
        })
    }

    /// Returns whether this context is for an authorization or resource server.
    #[must_use]
    pub const fn namespace(&self) -> NonceNamespace {
        self.namespace
    }
}

impl fmt::Debug for NonceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceContext")
            .field("namespace", &self.namespace)
            .field("server_id", &"[redacted]")
            .finish()
    }
}

/// Client-side nonce state capability scoped by issuing server context.
pub trait ClientNonceStore: Send + Sync {
    /// Returns the most recently accepted nonce for the context, if any.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when state cannot be read reliably.
    fn nonce_for(&self, context: &NonceContext) -> Result<Option<DpopNonce>, DpopPortError>;

    /// Records a nonce received in a nonce challenge.
    ///
    /// Once recorded, the reference implementation retains nonce-required state
    /// until explicitly replaced or forgotten; a later response without a nonce
    /// does not silently downgrade the context.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when the state cannot be recorded without
    /// violating the store's capacity guarantee.
    fn record_challenge(
        &self,
        context: &NonceContext,
        nonce: &DpopNonce,
    ) -> Result<(), DpopPortError>;

    /// Records an optional nonce received on a successful response.
    ///
    /// `None` leaves any established nonce requirement unchanged. `Some` replaces
    /// the current nonce for the next request to that exact context.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when state cannot be updated reliably.
    fn record_success(
        &self,
        context: &NonceContext,
        nonce: Option<&DpopNonce>,
    ) -> Result<(), DpopPortError>;
}

/// Bounded process-local client nonce cache.
///
/// The cache never evicts an active context merely to admit another context.
/// Capacity exhaustion therefore fails closed instead of losing established
/// nonce-required state.
pub struct InMemoryClientNonceStore {
    capacity: usize,
    entries: Mutex<HashMap<NonceContext, DpopNonce>>,
}

impl InMemoryClientNonceStore {
    /// Creates a bounded client nonce store.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidPolicy`] when `capacity` is zero.
    pub fn new(capacity: usize) -> Result<Self, DpopError> {
        if capacity == 0 {
            return Err(DpopError::InvalidPolicy);
        }
        Ok(Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Returns explicit topology, consistency, and capacity metadata.
    #[must_use]
    pub const fn metadata(&self) -> StateStoreMetadata {
        StateStoreMetadata {
            topology: StateStoreTopology::SingleProcess,
            consistency: StateStoreConsistency::ProcessLocalAtomic,
            capacity: self.capacity,
        }
    }

    /// Explicitly removes nonce state for a context as an application lifecycle action.
    ///
    /// This is intentionally not performed automatically by successful responses
    /// lacking a nonce, because that would permit nonce-enforcement downgrade.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when the store lock is unavailable.
    pub fn forget(&self, context: &NonceContext) -> Result<(), DpopPortError> {
        self.entries
            .lock()
            .map_err(|_| DpopPortError)?
            .remove(context);
        Ok(())
    }

    fn record(&self, context: &NonceContext, nonce: &DpopNonce) -> Result<(), DpopPortError> {
        let mut entries = self.entries.lock().map_err(|_| DpopPortError)?;
        if !entries.contains_key(context) && entries.len() >= self.capacity {
            return Err(DpopPortError);
        }
        entries.insert(context.clone(), nonce.clone());
        Ok(())
    }
}

impl fmt::Debug for InMemoryClientNonceStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryClientNonceStore")
            .field("metadata", &self.metadata())
            .field("entries", &"[redacted nonce state]")
            .finish()
    }
}

impl ClientNonceStore for InMemoryClientNonceStore {
    fn nonce_for(&self, context: &NonceContext) -> Result<Option<DpopNonce>, DpopPortError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| DpopPortError)?
            .get(context)
            .cloned())
    }

    fn record_challenge(
        &self,
        context: &NonceContext,
        nonce: &DpopNonce,
    ) -> Result<(), DpopPortError> {
        self.record(context, nonce)
    }

    fn record_success(
        &self,
        context: &NonceContext,
        nonce: Option<&DpopNonce>,
    ) -> Result<(), DpopPortError> {
        match nonce {
            Some(nonce) => self.record(context, nonce),
            None => Ok(()),
        }
    }
}

/// Capability for generating unpredictable server nonce values.
pub trait NonceGenerator: Send + Sync {
    /// Generates a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when secure generation fails.
    fn generate(&self) -> Result<DpopNonce, DpopPortError>;
}

/// Cryptographically strong reference nonce generator using 128 random bits.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomNonceGenerator;

impl NonceGenerator for RandomNonceGenerator {
    fn generate(&self) -> Result<DpopNonce, DpopPortError> {
        let random = SystemRandom::new();
        let mut bytes = [0_u8; GENERATED_NONCE_BYTES];
        random.fill(&mut bytes).map_err(|_| DpopPortError)?;
        DpopNonce::new(URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| DpopPortError)
    }
}

/// Server-side nonce enforcement capability scoped by issuing server context.
pub trait ServerNonceStore: Send + Sync {
    /// Returns the nonce currently required for the context, if enforcement has
    /// been established.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when state cannot be read reliably.
    fn expected_nonce(&self, context: &NonceContext) -> Result<Option<DpopNonce>, DpopPortError>;

    /// Issues or rotates the nonce for one context and establishes enforcement.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when generation/state update fails or capacity
    /// is exhausted for a previously unseen context.
    fn issue_nonce(&self, context: &NonceContext) -> Result<DpopNonce, DpopPortError>;
}

/// Bounded process-local server nonce state with explicit opt-in issuance.
pub struct InMemoryServerNonceStore<G> {
    generator: G,
    capacity: usize,
    entries: Mutex<HashMap<NonceContext, DpopNonce>>,
}

impl<G> InMemoryServerNonceStore<G>
where
    G: NonceGenerator,
{
    /// Creates a bounded server nonce store around an injected generator.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::InvalidPolicy`] when `capacity` is zero.
    pub fn new(generator: G, capacity: usize) -> Result<Self, DpopError> {
        if capacity == 0 {
            return Err(DpopError::InvalidPolicy);
        }
        Ok(Self {
            generator,
            capacity,
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Returns explicit topology, consistency, and capacity metadata.
    #[must_use]
    pub const fn metadata(&self) -> StateStoreMetadata {
        StateStoreMetadata {
            topology: StateStoreTopology::SingleProcess,
            consistency: StateStoreConsistency::ProcessLocalAtomic,
            capacity: self.capacity,
        }
    }

    /// Explicitly removes server nonce enforcement for an application-defined
    /// lifecycle boundary.
    ///
    /// # Errors
    ///
    /// Returns [`DpopPortError`] when the store lock is unavailable.
    pub fn forget(&self, context: &NonceContext) -> Result<(), DpopPortError> {
        self.entries
            .lock()
            .map_err(|_| DpopPortError)?
            .remove(context);
        Ok(())
    }
}

impl<G> fmt::Debug for InMemoryServerNonceStore<G>
where
    G: NonceGenerator,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryServerNonceStore")
            .field("metadata", &self.metadata())
            .field("entries", &"[redacted nonce state]")
            .finish()
    }
}

impl<G> ServerNonceStore for InMemoryServerNonceStore<G>
where
    G: NonceGenerator,
{
    fn expected_nonce(&self, context: &NonceContext) -> Result<Option<DpopNonce>, DpopPortError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| DpopPortError)?
            .get(context)
            .cloned())
    }

    fn issue_nonce(&self, context: &NonceContext) -> Result<DpopNonce, DpopPortError> {
        let nonce = self.generator.generate()?;
        let mut entries = self.entries.lock().map_err(|_| DpopPortError)?;
        if !entries.contains_key(context) && entries.len() >= self.capacity {
            return Err(DpopPortError);
        }
        entries.insert(context.clone(), nonce.clone());
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    use super::*;

    struct AtomicClock(AtomicI64);

    impl AtomicClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for AtomicClock {
        fn unix_seconds(&self) -> Result<i64, DpopPortError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Default)]
    struct SequenceNonceGenerator(AtomicU64);

    impl NonceGenerator for SequenceNonceGenerator {
        fn generate(&self) -> Result<DpopNonce, DpopPortError> {
            let value = self.0.fetch_add(1, Ordering::SeqCst);
            DpopNonce::new(format!("nonce-{value}")).map_err(|_| DpopPortError)
        }
    }

    fn key(byte: u8) -> ReplayKey {
        ReplayKey::new([byte; 32])
    }

    #[test]
    fn replay_ttl_retains_exact_acceptance_boundary() -> Result<(), DpopError> {
        let clock = AtomicClock::new(1_000);
        let store = InMemoryReplayStore::new(clock, 2)?;
        assert_eq!(
            store.check_and_record(&key(1), 1_600),
            Ok(ReplayStatus::Fresh)
        );
        store.clock.set(1_600);
        assert_eq!(
            store.check_and_record(&key(1), 1_600),
            Ok(ReplayStatus::Replay)
        );
        store.clock.set(1_601);
        assert_eq!(
            store.check_and_record(&key(1), 1_700),
            Ok(ReplayStatus::Fresh)
        );
        Ok(())
    }

    #[test]
    fn replay_capacity_never_evicts_an_active_marker() -> Result<(), DpopError> {
        let clock = AtomicClock::new(1_000);
        let store = InMemoryReplayStore::new(clock, 1)?;
        assert_eq!(
            store.check_and_record(&key(1), 1_600),
            Ok(ReplayStatus::Fresh)
        );
        assert!(store.check_and_record(&key(2), 1_600).is_err());
        assert_eq!(
            store.check_and_record(&key(1), 1_600),
            Ok(ReplayStatus::Replay)
        );
        store.clock.set(1_601);
        assert_eq!(
            store.check_and_record(&key(2), 1_700),
            Ok(ReplayStatus::Fresh)
        );
        Ok(())
    }

    #[test]
    fn client_nonce_state_is_namespaced_and_cannot_downgrade() -> Result<(), DpopError> {
        let store = InMemoryClientNonceStore::new(4)?;
        let as_context = NonceContext::new(NonceNamespace::AuthorizationServer, "issuer-a")?;
        let rs_context = NonceContext::new(NonceNamespace::ResourceServer, "issuer-a")?;
        let nonce = DpopNonce::new("required-nonce")?;

        store
            .record_challenge(&as_context, &nonce)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            store
                .nonce_for(&as_context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(nonce.clone())
        );
        assert_eq!(
            store
                .nonce_for(&rs_context)
                .map_err(|_| DpopError::NonceMismatch)?,
            None
        );

        store
            .record_success(&as_context, None)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            store
                .nonce_for(&as_context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(nonce)
        );
        Ok(())
    }

    #[test]
    fn successful_response_nonce_rotates_client_state() -> Result<(), DpopError> {
        let store = InMemoryClientNonceStore::new(2)?;
        let context = NonceContext::new(NonceNamespace::ResourceServer, "rs-a")?;
        let first = DpopNonce::new("nonce-1")?;
        let second = DpopNonce::new("nonce-2")?;
        store
            .record_challenge(&context, &first)
            .map_err(|_| DpopError::NonceMismatch)?;
        store
            .record_success(&context, Some(&second))
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            store
                .nonce_for(&context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(second)
        );
        Ok(())
    }

    #[test]
    fn server_nonce_enforcement_is_opt_in_and_sticky() -> Result<(), DpopError> {
        let store = InMemoryServerNonceStore::new(SequenceNonceGenerator::default(), 2)?;
        let context = NonceContext::new(NonceNamespace::ResourceServer, "rs-a")?;
        assert_eq!(
            store
                .expected_nonce(&context)
                .map_err(|_| DpopError::NonceMismatch)?,
            None
        );
        let first = store
            .issue_nonce(&context)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            store
                .expected_nonce(&context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(first)
        );
        let second = store
            .issue_nonce(&context)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert_eq!(
            store
                .expected_nonce(&context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(second)
        );
        Ok(())
    }

    #[test]
    fn nonce_capacity_does_not_evict_established_contexts() -> Result<(), DpopError> {
        let store = InMemoryClientNonceStore::new(1)?;
        let first_context = NonceContext::new(NonceNamespace::AuthorizationServer, "as-a")?;
        let second_context = NonceContext::new(NonceNamespace::AuthorizationServer, "as-b")?;
        let first_nonce = DpopNonce::new("nonce-a")?;
        let second_nonce = DpopNonce::new("nonce-b")?;
        store
            .record_challenge(&first_context, &first_nonce)
            .map_err(|_| DpopError::NonceMismatch)?;
        assert!(
            store
                .record_challenge(&second_context, &second_nonce)
                .is_err()
        );
        assert_eq!(
            store
                .nonce_for(&first_context)
                .map_err(|_| DpopError::NonceMismatch)?,
            Some(first_nonce)
        );
        Ok(())
    }

    #[test]
    fn reference_store_metadata_is_explicitly_single_process() -> Result<(), DpopError> {
        let replay = InMemoryReplayStore::new(AtomicClock::new(1_000), 8)?;
        let nonce = InMemoryClientNonceStore::new(8)?;
        for metadata in [replay.metadata(), nonce.metadata()] {
            assert_eq!(metadata.topology(), StateStoreTopology::SingleProcess);
            assert_eq!(
                metadata.consistency(),
                StateStoreConsistency::ProcessLocalAtomic
            );
            assert_eq!(metadata.capacity(), 8);
        }
        Ok(())
    }
}
