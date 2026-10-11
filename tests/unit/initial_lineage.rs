//! Actual Keys, Keyhole, certificate/assertion, Charter, CWST and NetworkBackend.
//! Nodes are independent validating LocalBackends. Only transport/persistence
//! faults are inert; strict completion fixtures do not establish live G3.
use super::*;
use cdht::Backend as _;
use cpky::software::{SoftwareAuthenticator, TestConfiguration};
use serde_json::json;

#[path = "initial_acknowledgment.rs"]
mod acknowledgment_tests;
#[path = "initial_enrollment.rs"]
mod enrollment_tests;

const ORIGIN: &str = "https://members.garden.example.test";
const RP: &str = "members.garden.example.test";

struct SameKey {
    client: cpky::Client<SoftwareAuthenticator>,
    descriptor: ckyh::lineage::PublicCredential,
    evidence: Vec<u8>,
    retained_checkpoint: Vec<u8>,
    renewed_certificate: Vec<u8>,
}
impl SameKey {
    async fn opening(&mut self) -> PreparedOpen {
        let (public, custody) = self
            .client
            .sign_in(serde_json::to_value(self.descriptor.request([29; 32])).unwrap())
            .await
            .unwrap()
            .into_parts();
        drop(public);
        match custody {
            cpky::VaultOutcome::Ready(unlock) => PreparedOpen::new(unlock, "garden").unwrap(),
            cpky::VaultOutcome::Locked(_) => panic!("original fixture PRF must be available"),
        }
    }
}

struct Completion {
    original: ExactCompletion,
    credential: Vec<u8>,
    packed: Vec<u8>,
    called: bool,
}
impl Completion {
    fn check_exact(&self, r: &ckmg::CompletionAuthorization<'_>) -> Result<(), ckmg::Error> {
        if r.receipt != &self.original.receipt
            || r.authority_reference != self.credential.as_slice()
            || r.location != &self.original.location
            || r.sealed_digest != &self.original.keys
            || r.intent.outer_generation != 2
            || r.intent.outer_digest != self.original.outer
            || r.intent.inner_version != 1
            || r.intent.inner_operation != [8; 32]
            || r.intent.inner_digest != self.original.inner
            || r.intent.nonce != [71; 24]
            || r.intent.packed_evidence != self.packed
            || r.intent.prepared_at != 10
            || r.intent.expires != 30
            || r.now != 10
        {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}
impl Authority for Completion {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
    async fn check_completion(
        &mut self,
        r: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        if self.called {
            return Err(ckmg::Error::Unauthorized);
        }
        self.check_exact(&r)?;
        self.called = true;
        TestClock(10).now()
    }
    fn check_completion_current(
        &mut self,
        r: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        if !std::mem::take(&mut self.called) {
            return Err(ckmg::Error::Unauthorized);
        }
        self.check_exact(&r)?;
        TestClock(10).now()
    }
}

fn charter(signer: &mut csgn::Signer) -> cchr::Charter {
    charter_members(signer, &[])
}

fn charter_members(signer: &mut csgn::Signer, revoked: &[&str]) -> cchr::Charter {
    // Same original signed five-document Charter construction as tests/lineage.
    fn sign(signer: &mut csgn::Signer, kind: csgn::Kind, payload: serde_json::Value) -> Vec<u8> {
        signer
            .sign(kind, &serde_json::to_vec(&payload).unwrap(), 10, 500)
            .unwrap()
    }
    let schema = json!({"community":"garden","version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"garden","revision":1,
        "policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),"schema_version":1});
    let mut feed = json!({"revision":1,"policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),
        "manifest":sign(signer,csgn::Kind::SettingsSnapshot,manifest)});
    for (name, kind, content) in [
        (
            "settings",
            csgn::Kind::SettingsSnapshot,
            json!({"action.admission":{"all_of":[],"any_of":[{"gate":"voucher"}],"k_of_n":{"k":1,"of":[{"gate":"voucher"}]}}}),
        ),
        ("schema", csgn::Kind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            csgn::Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        (
            "communities",
            csgn::Kind::CommunitiesSnapshot,
            json!(["garden"]),
        ),
        (
            "revocations",
            csgn::Kind::RevocationListSnapshot,
            json!({"members":revoked,"devices":[],"passkeys":[]}),
        ),
    ] {
        feed[name] = json!(sign(
            signer,
            kind,
            json!({"community":"garden","revision":1,"policy_epoch":1,"content":content})
        ));
    }
    let mut owner = cchr::Charter::new(cchr::Configuration {
        origin: ORIGIN.into(),
        community: "garden".into(),
        key_ring: signer.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    owner
        .install(&serde_json::to_vec(&feed).unwrap(), 10)
        .unwrap();
    owner
}

async fn genuine(destination: Destination) -> (InitialCreation<Destination>, SameKey) {
    // Real original registration and registered-key projection, not supplied SPKI.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let url = ckyh::Url::from_file_path(directory.path().join("keyhole.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(url.as_str(), "")))
        .unwrap();
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)]))
        .unwrap();
    let store = ckyh::LibsqlStore::new(&db, "garden", runtime.handle().clone()).unwrap();
    let server =
        ckyh::Passkeys::new(store, "garden", RP, &[ckyh::Url::parse(ORIGIN).unwrap()]).unwrap();
    let user = ckyh::Uuid::from_u128(17);
    let mut client = cpky::Client::new(
        cpky::Context::new(ORIGIN, RP).unwrap(),
        SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    );
    let (options, pending) = server.start_registration(user).unwrap();
    let (public, unlock) = client
        .register_member(serde_json::to_value(options).unwrap())
        .await
        .unwrap()
        .into_parts();
    let credential = public.credential_id().unwrap();
    let response = serde_json::from_value(public.into_json()).unwrap();
    let stored = server
        .finish_registration(
            pending,
            &response,
            ckyh::CreationMonth::new(2026, 10).unwrap(),
        )
        .unwrap();
    assert_eq!(stored.credential_id().as_ref(), credential);
    let descriptor = server
        .registered_public_credential(user, stored.credential_id())
        .unwrap();
    let registration = server
        .registration_certificate(user, stored.credential_id(), "original")
        .unwrap();
    let mut persistent = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "garden",
        csgn::SecretKey::from_seed(&mut [77; 32]),
        9,
        60,
    )
    .await
    .unwrap();
    let certificate = registration.sign(&mut persistent, 10).await.unwrap();
    let renewed_certificate = server
        .registration_certificate(user, stored.credential_id(), "original")
        .unwrap()
        .sign(&mut persistent, 70)
        .await
        .unwrap();
    let input = PreparedOpen::new(unlock, "garden").unwrap();
    let device = input.device().unwrap();
    let created = input
        .create_recoverable(
            destination,
            ckmg::Binding::new("garden", "original").unwrap(),
            ckmg::DeviceInfo::new("fixture", &credential).unwrap(),
            b"original creation fixture",
            Batch {
                expected: 0,
                operation: [8; 32],
                mutations: vec![],
                outputs: vec![],
            },
            Owners {
                clock: TestClock(10),
                entropy: FixtureEntropy,
                authority: CreateOnce {
                    device,
                    consumed: Rc::new(Cell::new(false)),
                },
                records: UnavailableRecords,
                wallet: (),
            },
        )
        .await
        .unwrap();
    let challenge = created.receipt().passkey_challenge().unwrap();
    let (public, custody) = client
        .sign_in(serde_json::to_value(descriptor.request(challenge)).unwrap())
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    let response: ckyh::PublicKeyCredential = serde_json::from_value(public.into_json()).unwrap();
    let assertion = ckyh::lineage::Assertion {
        credential_id: response.raw_id.as_ref().to_vec(),
        client_data_json: response.response.client_data_json.as_ref().to_vec(),
        authenticator_data: response.response.authenticator_data.as_ref().to_vec(),
        signature: response.response.signature.as_ref().to_vec(),
        user_handle: response
            .response
            .user_handle
            .as_ref()
            .map(|value| value.as_ref().to_vec()),
    };
    ckyh::lineage::verify(&descriptor, &assertion, challenge).unwrap();
    let mut signer =
        csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [77; 32]), 9, 1000).unwrap();
    let mut current = charter(&mut signer);
    let evidence = crate::LineageEvidence::prepare(
        current.current(10).unwrap(),
        created.receipt(),
        &assertion,
        &certificate,
        "original",
        10,
    )
    .unwrap();
    let packed = evidence.evidence().packed().unwrap().to_vec();
    let evidence_bytes = evidence.evidence().to_bytes().unwrap();
    let initial = created
        .prepare(&evidence, 30, &mut TestClock(10), &mut FixtureEntropy)
        .await
        .unwrap();
    let mut completion = Completion {
        original: ExactCompletion::new(&initial),
        credential,
        packed,
        called: false,
    };
    let retained = initial
        .retain(&mut TestClock(10), &mut completion)
        .await
        .unwrap();
    let retained_checkpoint = retained.store.sealed_checkpoint().unwrap().to_vec();
    (
        retained,
        SameKey {
            client,
            descriptor,
            evidence: evidence_bytes,
            retained_checkpoint,
            renewed_certificate,
        },
    )
}

#[derive(Clone)]
struct Network {
    nodes: Rc<
        Vec<(
            cdht::NodeId,
            cdht::LocalBackend<crate::records::tor::Verifier>,
        )>,
    >,
    candidates: Rc<Vec<cdht::NodeId>>,
    gets: Rc<Cell<u32>>,
    sets: Rc<Cell<u32>>,
    unavailable: Rc<Cell<bool>>,
    gate: Rc<futures::lock::Mutex<()>>,
}
impl Network {
    async fn new(descriptor: &cdht::Descriptor, values: &[Option<cdht::SignedValue>]) -> Self {
        let mut nodes = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let backend = cdht::LocalBackend::new(crate::records::tor::Verifier);
            backend.create(descriptor).await.unwrap();
            if let Some(value) = value {
                backend.set(&descriptor.key(), 0, value).await.unwrap();
            }
            nodes.push(([(index + 1) as u8; 32], backend));
        }
        Self {
            candidates: Rc::new(nodes.iter().map(|(id, _)| *id).collect()),
            nodes: Rc::new(nodes),
            gets: Rc::new(Cell::new(0)),
            sets: Rc::new(Cell::new(0)),
            unavailable: Rc::new(Cell::new(false)),
            gate: Rc::new(futures::lock::Mutex::new(())),
        }
    }
    fn node(&self, node: &cdht::NodeId) -> &cdht::LocalBackend<crate::records::tor::Verifier> {
        &self.nodes.iter().find(|(id, _)| id == node).unwrap().1
    }
}
impl cdht::Network for Network {
    fn now_ms(&self) -> u64 {
        10_000
    }
    async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        Ok((*self.candidates).clone())
    }
    async fn descriptor(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        self.node(node).descriptor(key).await
    }
    async fn get(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
        subkey: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        self.gets.set(self.gets.get() + 1);
        let _held = self.gate.lock().await;
        if self.unavailable.get() {
            return Err(cdht::Error::Unavailable);
        }
        self.node(node).get(key, subkey).await
    }
    async fn set(
        &self,
        _: &cdht::NodeId,
        _: &cdht::Descriptor,
        _: u32,
        _: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        self.sets.set(self.sets.get() + 1);
        Err(cdht::Error::Unavailable)
    }
    async fn watch(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
    ) -> Result<cdht::WatchId, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<(), cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn changes(
        &self,
        _: &cdht::NodeId,
        _: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}
struct ClockCell(Rc<Cell<u64>>);
impl Clock for ClockCell {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(self.0.get())
    }
}

shared!(
    three_real_holders_yield_only_exact_unacknowledged_lineage_evidence,
    {
        let destination = Destination::new();
        let (initial, mut same_key) = genuine(destination.clone()).await;
        let receipt = initial.receipt().clone();
        let pair = initial.retained().unwrap();
        let descriptor = pair.descriptor.decode().unwrap();
        let value = pair.value.decode().unwrap();
        drop(initial.stage(PublicationBackend::new()).await.unwrap());
        let committed = destination.memory.read().await.unwrap().unwrap();
        let initial = same_key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        let network = Network::new(
            &descriptor,
            &[Some(value.clone()), Some(value.clone()), Some(value)],
        )
        .await;
        let witness = initial
            .read_first_lineage(network.clone(), &mut TestClock(10))
            .await
            .unwrap();
        assert_eq!(network.gets.get(), 3);
        assert_eq!(network.sets.get(), 0);
        assert_eq!(witness.receipt(), &receipt);
        assert_eq!(witness.evidence().operation(), receipt.operation.as_bytes());
        assert_eq!(witness.evidence().to_bytes().unwrap(), same_key.evidence);
        assert_eq!(witness.checked_at(), 10);
        drop(witness);
        assert_eq!(destination.memory.read().await.unwrap(), Some(committed));
        let reopened = same_key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
        assert_eq!(reopened.store.load_pending().unwrap().len(), 2);
        assert_eq!(reopened.staged_state().unwrap().queue().len(), 1);
        assert_eq!(destination.writes.get(), 4);
    }
);

shared!(
    partial_missing_unavailable_and_duplicate_holders_never_yield_witness,
    {
        for case in 0..4 {
            let destination = Destination::new();
            let (initial, mut same_key) = genuine(destination.clone()).await;
            let pair = initial.retained().unwrap();
            let descriptor = pair.descriptor.decode().unwrap();
            let value = pair.value.decode().unwrap();
            drop(initial.stage(PublicationBackend::new()).await.unwrap());
            let committed = destination.memory.read().await.unwrap().unwrap();
            let initial = same_key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            let values = if case == 1 {
                vec![None, None, None]
            } else {
                vec![Some(value.clone()), Some(value), None]
            };
            let mut network = Network::new(&descriptor, &values).await;
            if case == 2 {
                network.unavailable.set(true);
            }
            if case == 3 {
                network.candidates = Rc::new(vec![network.nodes[0].0; 3]);
            }
            assert!(matches!(
                initial
                    .read_first_lineage(network.clone(), &mut TestClock(10))
                    .await,
                Err(InitialError::Records(crate::RecordError::Unavailable))
                    | Err(InitialError::Publication(cdht::Error::Unavailable))
            ));
            assert_eq!(network.sets.get(), 0);
            assert_eq!(destination.memory.read().await.unwrap(), Some(committed));
            assert_eq!(destination.writes.get(), 4);
        }
    }
);

shared!(
    one_signed_conflict_fences_genesis_without_quorum_and_preserves_obligation,
    {
        for seq in [0, 1] {
            let destination = Destination::new();
            let (initial, mut same_key) = genuine(destination.clone()).await;
            let pair = initial.retained().unwrap();
            let descriptor = pair.descriptor.decode().unwrap();
            let signer = FixtureSigner(SigningKey::from_bytes(&[71; 32]));
            assert_eq!(cdht::Signer::public_key(&signer), descriptor.owner);
            let conflict = cdht::SignedValue::sign_with_nonce(
                &descriptor.owner,
                0,
                seq,
                b"different genuine original root-signed observation".to_vec(),
                Some([99; 24]),
                &signer,
            )
            .unwrap();
            drop(initial.stage(PublicationBackend::new()).await.unwrap());
            let initial = same_key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            let network = Network::new(&descriptor, &[Some(conflict.clone()), None, None]).await;
            assert!(matches!(
                initial
                    .read_first_lineage(network.clone(), &mut TestClock(10))
                    .await,
                Err(InitialError::Publication(cdht::Error::Conflict))
            ));
            assert_eq!(network.sets.get(), 0);
            let reopened = same_key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            assert_eq!(reopened.phase().unwrap(), InitialPhase::Conflicted);
            let state = reopened.conflicted_state().unwrap();
            assert_eq!(state.queue().len(), 1);
            assert_eq!(state.queue()[0].value, pair.value.decode().unwrap());
            assert_eq!(reopened.store.load_pending().unwrap().len(), 2);
            let mut observed = cdht::Dht::with_state(
                cdht::LocalBackend::new(crate::records::tor::Verifier),
                crate::records::tor::Verifier,
                state,
            );
            assert_eq!(
                observed.get_signed(&descriptor.key(), 0).await.unwrap(),
                Some(conflict)
            );
            assert!(matches!(
                reopened.resume_publication(PublicationBackend::new()),
                Err(InitialError::Invalid)
            ));
            assert_eq!(destination.writes.get(), 5);
        }
    }
);

shared!(
    network_wait_rechecks_deadline_clock_and_actual_checkpoint_and_cancels_cleanly,
    {
        for case in 0..4 {
            let destination = Destination::new();
            let (initial, mut same_key) = genuine(destination.clone()).await;
            let old = destination.memory.read().await.unwrap().unwrap();
            let pair = initial.retained().unwrap();
            let descriptor = pair.descriptor.decode().unwrap();
            let value = pair.value.decode().unwrap();
            drop(initial.stage(PublicationBackend::new()).await.unwrap());
            let committed = destination.memory.read().await.unwrap().unwrap();
            let initial = same_key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            let network = Network::new(
                &descriptor,
                &[Some(value.clone()), Some(value.clone()), Some(value)],
            )
            .await;
            let held = network.gate.lock().await;
            let time = Rc::new(Cell::new(10));
            let mut clock = ClockCell(time.clone());
            let mut pending = Box::pin(initial.read_first_lineage(network.clone(), &mut clock));
            assert!(pending.as_mut().now_or_never().is_none());
            assert_eq!(network.gets.get(), 1);
            match case {
                0 => time.set(30),
                1 => time.set(9),
                2 => destination
                    .memory
                    .compare_exchange(Some(&committed), &old)
                    .await
                    .unwrap(),
                3 => {}
                _ => unreachable!(),
            }
            if case == 3 {
                drop(pending);
                drop(held);
                assert_eq!(destination.memory.read().await.unwrap(), Some(committed));
                let reopened = same_key
                    .opening()
                    .await
                    .reopen_initial(destination.clone())
                    .await
                    .unwrap();
                assert!(
                    reopened
                        .read_first_lineage(network.clone(), &mut TestClock(10))
                        .await
                        .is_ok()
                );
            } else {
                drop(held);
                let result = pending.await;
                match case {
                    0 => assert!(matches!(
                        result,
                        Err(InitialError::Keys(ckmg::Error::Expired))
                    )),
                    1 => assert!(matches!(
                        result,
                        Err(InitialError::Keys(ckmg::Error::Clock))
                    )),
                    2 => assert!(matches!(
                        result,
                        Err(InitialError::Storage(cwst::Error::Conflict))
                    )),
                    _ => unreachable!(),
                }
            }
            assert_eq!(network.sets.get(), 0);
            assert_eq!(destination.writes.get(), 4);
        }
    }
);

// This is original-owner cryptographic verification only. The production
// acknowledged-candidate constructor separately enforces the durable phase and
// initial enrollment provenance; these older lower fixtures cannot mint it.
shared!(
    renewed_same_key_verifies_immutable_assertion_at_present_time_only,
    {
        let (initial, key) = genuine(Destination::new()).await;
        assert!(initial.acknowledged_candidate().is_err());
        let original = crate::LineageEvidence::from_bytes(&key.evidence).unwrap();
        let unchanged = original.to_bytes().unwrap();
        let mut signer =
            csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [77; 32]), 9, 1000)
                .unwrap();
        let mut owner = charter(&mut signer);
        let current = owner.current(70).unwrap();
        assert!(original.verify(current, "original", 70).is_err());
        let renewed = original
            .reauthorize_initial(current, &key.renewed_certificate, "original", 70)
            .unwrap();
        assert_eq!(
            renewed.lineage(70).unwrap(),
            initial.receipt().attested_lineage().unwrap().0
        );
        assert_eq!(
            renewed.credential_id(70).unwrap(),
            key.descriptor.credential_id()
        );
        assert!(renewed.lineage(69).is_err());
        assert!(
            original
                .reauthorize_initial(current, &key.renewed_certificate, "foreign", 70)
                .is_err()
        );
        assert!(
            original
                .reauthorize_initial(current, &key.renewed_certificate, "original", 130)
                .is_err()
        );
        let (_, other) = genuine(Destination::new()).await;
        assert!(
            original
                .reauthorize_initial(current, &other.renewed_certificate, "original", 70)
                .is_err()
        );
        assert_eq!(original.to_bytes().unwrap(), unchanged);
        let mut revoked = charter_members(&mut signer, &["original"]);
        assert!(
            original
                .reauthorize_initial(
                    revoked.current(70).unwrap(),
                    &key.renewed_certificate,
                    "original",
                    70,
                )
                .is_err()
        );
    }
);
