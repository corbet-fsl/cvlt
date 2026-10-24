//! Real CPky/Keyhole registration and original CWST enrollment transitions.
//! The exact checker is not an HTTPS membership lease or production G3 adapter.
use super::*;

struct Enrolling {
    _runtime: tokio::runtime::Runtime,
    _directory: tempfile::TempDir,
    server: ckyh::Passkeys<ckyh::LibsqlStore>,
    scope: &'static str,
    member: String,
    client: cpky::Client<SoftwareAuthenticator>,
    pending: Option<ckyh::PendingRegistration>,
    public: Option<ckyh::RegisterPublicKeyCredential>,
    original_id: Vec<u8>,
    seed: [u8; 32],
    device: ckmg::PublicKey,
    inspector: ckmg::CheckpointInspector,
    cipher: ckmg::passkey::StoreCipher,
    location: ckmg::Locator,
    candidate_digest: Option<[u8; 32]>,
    opening: Option<PreparedOpen>,
    initial: Option<crate::UnenrolledInitial<Destination>>,
}
impl Enrolling {
    async fn new(destination: Destination) -> Self {
        Self::with_retention_mode(destination, 0).await
    }
    async fn with_retention_mode(destination: Destination, mode: u8) -> Self {
        Self::in_realm(destination, mode, "garden", ORIGIN, RP, "original".into()).await
    }
    async fn in_realm(
        destination: Destination,
        mode: u8,
        scope: &'static str,
        origin: &'static str,
        rp: &'static str,
        member: String,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let url = ckyh::Url::from_file_path(directory.path().join("keys.db")).unwrap();
        let db = runtime
            .block_on(crlt::Db::open(crlt::Config::new(url.as_str(), "")))
            .unwrap();
        runtime
            .block_on(db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)]))
            .unwrap();
        let store = ckyh::LibsqlStore::new(&db, scope, runtime.handle().clone()).unwrap();
        let server =
            ckyh::Passkeys::new(store, scope, rp, &[ckyh::Url::parse(origin).unwrap()]).unwrap();
        let seed = ckmg::EnrollmentSeed::new(
            ckmg::Binding::new(scope, &member).unwrap(),
            &mut ckmg::SystemEntropy,
        )
        .unwrap();
        let commitment = seed.commitment().unwrap();
        let (options, pending) = server
            .start_initial_registration(ckyh::Uuid::from_u128(17), Some(commitment))
            .unwrap();
        let mut client = cpky::Client::new(
            cpky::Context::new(origin, rp).unwrap(),
            SoftwareAuthenticator::new(
                origin,
                TestConfiguration {
                    user_verified: true,
                    prf: true,
                    evaluate_at_create: false,
                },
            )
            .unwrap(),
        );
        let (public, custody) = client
            .register_member(serde_json::to_value(options).unwrap())
            .await
            .unwrap()
            .into_parts();
        let original_id = public.credential_id().unwrap();
        let finish_continuation = serde_json::to_vec(&public).unwrap();
        let public = serde_json::from_value(public.into_json()).unwrap();
        let opening = PreparedOpen::new(custody, scope).unwrap();
        let device = opening.device().unwrap();
        let inspector = opening.inspector().unwrap();
        let cipher = ckmg::passkey::store_cipher(&opening.prf, scope).unwrap();
        let location = opening.locator;
        destination.mode.set(mode);
        let mut clock = TestClock(10);
        let mut entropy = ckmg::SystemEntropy;
        let retention = opening.retain_enrollment(
            destination.clone(),
            seed,
            ckmg::DeviceInfo::new("fixture", &original_id).unwrap(),
            &finish_continuation,
            &mut clock,
            &mut entropy,
        );
        let retained = match mode {
            0 => Some(retention.await.unwrap()),
            1 | 2 => {
                assert!(retention.now_or_never().is_none());
                None
            }
            3 => {
                assert!(retention.await.is_err());
                None
            }
            _ => unreachable!(),
        };
        destination.mode.set(0);
        if let Some(retained) = &retained {
            assert_eq!(retained.commitment().unwrap(), commitment);
            assert_eq!(retained.finish_continuation().unwrap(), finish_continuation);
        }
        let candidate_digest = if destination.memory.read().await.unwrap().is_some() {
            let actual = cwst::Store::open(destination.memory.clone(), &cipher, scope)
                .await
                .unwrap();
            assert_eq!(
                required(&actual, ENROLLMENT_FINISH).unwrap(),
                finish_continuation
            );
            Some(*blake3::hash(required(&actual, ENROLLMENT).unwrap()).as_bytes())
        } else {
            None
        };
        // Server acceptance has not occurred. Only the durable private candidate
        // exists; every public receipt/normal Keys path remains unavailable.
        assert!(server.list(ckyh::Uuid::from_u128(17)).unwrap().is_empty());
        Self {
            _runtime: runtime,
            _directory: directory,
            server,
            scope,
            member,
            client,
            pending: Some(pending),
            public: Some(public),
            original_id,
            seed: commitment,
            device,
            inspector,
            cipher,
            location,
            candidate_digest,
            opening: None,
            initial: retained,
        }
    }
    async fn accept(&mut self) -> ckyh::Authentication {
        let stored = self
            .server
            .finish_registration(
                self.pending.take().unwrap(),
                &self.public.take().unwrap(),
                ckyh::CreationMonth::new(2026, 10).unwrap(),
            )
            .unwrap();
        assert_eq!(stored.credential_id().as_ref(), self.original_id);
        self.authenticate().await
    }
    async fn authenticate(&mut self) -> ckyh::Authentication {
        let (options, pending) = self
            .server
            .start_authentication(ckyh::Uuid::from_u128(17))
            .unwrap();
        let (public, custody) = self
            .client
            .sign_in(serde_json::to_value(options).unwrap())
            .await
            .unwrap()
            .into_parts();
        let public = serde_json::from_value(public.into_json()).unwrap();
        let authentication = self.server.finish_authentication(pending, &public).unwrap();
        let unlock = match custody {
            cpky::VaultOutcome::Ready(unlock) => unlock,
            _ => panic!("original fixture PRF must be available"),
        };
        self.opening = Some(PreparedOpen::new(unlock, self.scope).unwrap());
        authentication
    }
    async fn reopen(&mut self, destination: Destination) -> crate::UnenrolledInitial<Destination> {
        self.authenticate().await;
        self.opening
            .take()
            .unwrap()
            .reopen_enrollment(destination)
            .await
            .unwrap()
    }
}

struct Activation<'a> {
    server: &'a ckyh::Passkeys<ckyh::LibsqlStore>,
    binding: ckmg::Binding,
    auth: ckyh::Authentication,
    credential: Vec<u8>,
    device: ckmg::PublicKey,
    seed: [u8; 32],
    durable: ckmg::InitialActivationIntent,
    location: ckmg::Locator,
    candidate_digest: [u8; 32],
    time: Rc<Cell<u64>>,
    deny: bool,
    checks: usize,
}
impl Activation<'_> {
    fn exact(&self, r: &ckmg::InitialActivationAuthorization<'_>) -> Result<u64, ckmg::Error> {
        let original = self
            .server
            .initial_creation(&self.auth)
            .map_err(|_| ckmg::Error::Unauthorized)?;
        if self.deny
            || r.binding != &self.binding
            || (self.binding.community() == "wallet"
                && self.binding.member() != self.auth.member().to_string())
            || r.authority_reference != self.credential.as_slice()
            || r.authority_reference != self.auth.credential_id().as_ref()
            || r.device != self.device
            || r.seed != &self.seed
            || original.seed() != self.seed
            || original.publication().is_some()
            || r.durable.generation != self.durable.generation
            || r.durable.digest != self.durable.digest
            || r.location != &self.location
            || r.sealed_digest != &self.candidate_digest
            || r.operation.as_bytes() == &[0; 32]
            || r.now != self.time.get()
            || !(10..30).contains(&r.now)
        {
            return Err(ckmg::Error::Unauthorized);
        }
        TestClock(self.time.get()).now()
    }
}
impl Authority for Activation<'_> {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
    async fn check_initial_activation(
        &mut self,
        r: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.checks += 1;
        self.exact(&r)
    }
    fn check_initial_activation_current(
        &mut self,
        r: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.checks += 1;
        self.exact(&r)
    }
}
fn activation<'a>(
    f: &'a Enrolling,
    auth: ckyh::Authentication,
    pending: &crate::UnenrolledInitial<Destination>,
) -> Activation<'a> {
    Activation {
        server: &f.server,
        binding: ckmg::Binding::new(f.scope, &f.member).unwrap(),
        auth,
        credential: f.original_id.clone(),
        device: f.device,
        seed: f.seed,
        durable: pending.activation_intent().unwrap(),
        location: f.location,
        candidate_digest: f.candidate_digest.unwrap(),
        time: Rc::new(Cell::new(10)),
        deny: false,
        checks: 0,
    }
}
struct Deny;
impl Authority for Deny {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
}

shared!(
    candidate_is_durable_before_real_finish_and_activation_keeps_one_original_root,
    {
        let destination = Destination::new();
        let mut f = Enrolling::new(destination.clone()).await;
        let original = destination.memory.read().await.unwrap().unwrap();
        let pending = f.initial.take().unwrap();
        let outer = cwst::Store::open(destination.memory.clone(), &f.cipher, "garden")
            .await
            .unwrap();
        let candidate = required(&outer, ENROLLMENT).unwrap();
        assert!(f.inspector.inspect(candidate).is_err());
        assert!(f.inspector.pending_creation(candidate).is_err());
        let saved_finish = pending.finish_continuation().unwrap().to_vec();
        let actual_public: ckyh::RegisterPublicKeyCredential =
            serde_json::from_slice(&saved_finish).unwrap();
        f.public = Some(actual_public);
        let auth = f.accept().await;
        let mut owner = activation(&f, auth, &pending);
        let accepted = pending
            .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut owner)
            .await
            .unwrap();
        assert_eq!(owner.checks, 3);
        assert_eq!(accepted.phase().unwrap(), InitialPhase::Pending);
        assert_eq!(accepted.store.version().unwrap(), 2);
        assert_eq!(destination.writes.get(), 2);
        assert_ne!(destination.memory.read().await.unwrap().unwrap(), original);
        assert_eq!(
            initial_operation(&accepted.store).unwrap(),
            *accepted.receipt().operation.as_bytes()
        );
        let receipt = accepted.receipt().clone();
        drop(accepted);
        drop(owner);
        f.authenticate().await;
        let reopened = f
            .opening
            .take()
            .unwrap()
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.receipt(), &receipt);
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Pending);
        assert_eq!(reopened.store.version().unwrap(), 2);
        f.authenticate().await;
        assert!(
            f.opening
                .take()
                .unwrap()
                .reopen_enrollment(destination.clone())
                .await
                .is_err()
        );
        assert_eq!(destination.writes.get(), 2);
    }
);

shared!(
    default_authority_and_wrong_seed_refuse_without_advancing_the_actual_store,
    {
        let destination = Destination::new();
        let mut f = Enrolling::new(destination.clone()).await;
        let original = destination.memory.read().await.unwrap().unwrap();
        let auth = f.accept().await;
        assert!(
            f.initial
                .take()
                .unwrap()
                .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut Deny)
                .await
                .is_err()
        );
        assert_eq!(destination.memory.read().await.unwrap().unwrap(), original);
        let pending = f.reopen(destination.clone()).await;
        let mut owner = activation(&f, auth, &pending);
        owner.seed[0] ^= 1;
        assert!(
            pending
                .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut owner)
                .await
                .is_err()
        );
        assert_eq!(destination.memory.read().await.unwrap().unwrap(), original);
        assert_eq!(destination.writes.get(), 1);
    }
);

shared!(
    unknown_and_cancelled_actual_outer_cas_reopen_the_winning_phase,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let mut f = Enrolling::new(destination.clone()).await;
            let auth = f.accept().await;
            let pending = f.initial.take().unwrap();
            let mut owner = activation(&f, auth, &pending);
            destination.mode.set(mode);
            let mut clock = TestClock(10);
            let mut entropy = ckmg::SystemEntropy;
            let future = pending.activate(&mut clock, &mut entropy, &mut owner);
            if mode == 3 {
                assert!(future.await.is_err());
            } else {
                assert!(future.now_or_never().is_none());
            }
            drop(owner);
            destination.mode.set(0);
            f.authenticate().await;
            if mode == 1 {
                let pending = f
                    .opening
                    .take()
                    .unwrap()
                    .reopen_enrollment(destination.clone())
                    .await
                    .unwrap();
                assert_eq!(pending.commitment().unwrap(), f.seed);
                let auth = f.authenticate().await;
                let mut owner = activation(&f, auth, &pending);
                assert!(
                    pending
                        .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut owner)
                        .await
                        .is_ok()
                );
            } else {
                let accepted = f
                    .opening
                    .take()
                    .unwrap()
                    .reopen_initial(destination.clone())
                    .await
                    .unwrap();
                assert_eq!(accepted.phase().unwrap(), InitialPhase::Pending);
                assert_eq!(accepted.store.version().unwrap(), 2);
            }
            assert!(destination.memory.read().await.unwrap().is_some());
        }
    }
);

shared!(
    cloned_candidate_cannot_commit_twice_and_postcas_expiry_withholds_result,
    {
        let destination = Destination::new();
        let mut f = Enrolling::new(destination.clone()).await;
        let auth = f.accept().await;
        let first = f.initial.take().unwrap();
        let second = f.reopen(destination.clone()).await;
        let mut a = activation(&f, auth.clone(), &first);
        let mut b = activation(&f, auth, &second);
        first
            .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut a)
            .await
            .unwrap();
        assert!(
            second
                .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut b)
                .await
                .is_err()
        );
        assert_eq!(destination.writes.get(), 2);
        drop((a, b));

        let destination = Destination::new();
        let mut f = Enrolling::new(destination.clone()).await;
        let auth = f.accept().await;
        let pending = f.initial.take().unwrap();
        let mut owner = activation(&f, auth, &pending);
        let time = owner.time.clone();
        let gate = destination.read_gate.lock().await;
        destination.mode.set(6);
        let mut clock = ClockCell(time.clone());
        let mut entropy = ckmg::SystemEntropy;
        let mut future = Box::pin(pending.activate(&mut clock, &mut entropy, &mut owner));
        assert!(futures::poll!(future.as_mut()).is_pending());
        time.set(30);
        destination.mode.set(0);
        drop(gate);
        assert!(future.await.is_err());
        drop(owner);
        f.authenticate().await;
        let accepted = f
            .opening
            .take()
            .unwrap()
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(accepted.phase().unwrap(), InitialPhase::Pending);
        assert_eq!(destination.writes.get(), 2);
    }
);

shared!(
    first_candidate_cas_cancellation_retains_finish_atomically_before_server_acceptance,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let mut f = Enrolling::with_retention_mode(destination.clone(), mode).await;
            assert!(f.initial.is_none());
            assert!(f.server.list(ckyh::Uuid::from_u128(17)).unwrap().is_empty());
            if mode == 1 {
                // No accepting server mutation may follow a missing durable
                // candidate. No new seed or replacement root is generated.
                assert!(destination.memory.read().await.unwrap().is_none());
                assert_eq!(destination.writes.get(), 1); // one attempted, uncommitted CAS
                continue;
            }
            let actual = cwst::Store::open(destination.memory.clone(), &f.cipher, "garden")
                .await
                .unwrap();
            assert_eq!(actual.version().unwrap(), 1);
            let candidate = required(&actual, ENROLLMENT).unwrap();
            assert!(f.inspector.inspect(candidate).is_err());
            assert!(f.inspector.pending_creation(candidate).is_err());
            // Discard the transient finish bytes and recover the exact original
            // public credential from the same durable encrypted transaction.
            f.public.take();
            f.public = Some(
                serde_json::from_slice(required(&actual, ENROLLMENT_FINISH).unwrap()).unwrap(),
            );
            let auth = f.accept().await;
            let pending = f.reopen(destination.clone()).await;
            assert_eq!(pending.commitment().unwrap(), f.seed);
            let mut owner = activation(&f, auth, &pending);
            let accepted = pending
                .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut owner)
                .await
                .unwrap();
            assert_eq!(accepted.phase().unwrap(), InitialPhase::Pending);
            assert_eq!(accepted.store.version().unwrap(), 2);
            assert_eq!(destination.writes.get(), 2);
        }
    }
);

/// Activation authority of a device-key member: the candidate's authority reference is the
/// device key itself (the key `device_join` registered), never a passkey credential.
struct DeviceOwner {
    device: ckmg::PublicKey,
    seed: [u8; 32],
}
impl DeviceOwner {
    fn exact(&self, r: &ckmg::InitialActivationAuthorization<'_>) -> Result<u64, ckmg::Error> {
        if r.device != self.device
            || r.authority_reference != self.device.value()
            || r.seed != &self.seed
        {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(30)
    }
}
impl Authority for DeviceOwner {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
    async fn check_initial_activation(
        &mut self,
        r: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.exact(&r)
    }
    fn check_initial_activation_current(
        &mut self,
        r: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.exact(&r)
    }
}

shared!(
    device_enrollment_commits_its_genesis_time_and_signs_only_fixed_purposes_before_activation,
    {
        let destination = Destination::new();
        let prepared = opening(9, "garden");
        let device = prepared.device().unwrap();
        let cipher = ckmg::passkey::store_cipher(&prepared.prf, "garden").unwrap();
        let seed = ckmg::EnrollmentSeed::new(
            ckmg::Binding::new("garden", "member").unwrap(),
            &mut ckmg::SystemEntropy,
        )
        .unwrap();
        let commitment = seed.commitment().unwrap();
        let pending = prepared
            .retain_device_enrollment(
                destination.clone(),
                seed,
                "phone",
                &mut TestClock(20),
                &mut ckmg::SystemEntropy,
            )
            .await
            .unwrap();
        assert_eq!(pending.commitment().unwrap(), commitment);
        assert_eq!(pending.genesis_at().unwrap(), 20);
        // No passkey ceremony: there is no finish continuation to replay.
        assert_eq!(pending.finish_continuation(), Err(InitialError::Invalid));
        // One version-1 commit: the candidate and its eight-byte time, nothing else.
        let outer = cwst::Store::open(destination.memory.clone(), &cipher, "garden")
            .await
            .unwrap();
        assert_eq!(outer.version().unwrap(), 1);
        assert_eq!(destination.writes.get(), 1);
        assert_eq!(
            required(&outer, ENROLLMENT_GENESIS_AT).unwrap(),
            20u64.to_le_bytes()
        );
        assert!(outer.read(OWNER, ENROLLMENT_FINISH).unwrap().is_none());
        let challenge = pending.passkey_challenge().unwrap();
        let salt = [5; 32];
        assert_eq!(
            pending.lineage_genesis_action(salt).unwrap(),
            cchr::lineage_genesis_action_for(challenge, salt, 20).unwrap()
        );
        let payload = b"garden, challenge, key";
        let signature = pending
            .sign_device(ckmg::DeviceFormat::DeviceJoin, payload)
            .unwrap();
        let signed = [ckmg::DeviceFormat::DeviceJoin.tag(), &payload[..]].concat();
        ckmg::verify_ed25519(device.value(), &signed, &signature).unwrap();
        drop(pending);
        // A restart rebuilds the same time, challenge and action from durable state.
        let pending = opening(9, "garden")
            .reopen_enrollment(destination.clone())
            .await
            .unwrap();
        assert_eq!(pending.genesis_at().unwrap(), 20);
        assert_eq!(pending.passkey_challenge().unwrap(), challenge);
        assert_eq!(
            pending
                .sign_device(ckmg::DeviceFormat::DeviceJoin, payload)
                .unwrap(),
            signature
        );
        // The opening alone signs the session message with the same key (a device restarted
        // after activation), equal to the enrollment's session signature.
        let session = opening(9, "garden").sign_device_session(payload).unwrap();
        assert_eq!(
            pending
                .sign_device(ckmg::DeviceFormat::DeviceSession, payload)
                .unwrap(),
            session
        );
        // It rebuilds the salt bit-exact; the enrollment never signs the salt message.
        assert_eq!(
            opening(9, "garden").device_salt(payload).unwrap(),
            pending.device_salt(payload).unwrap()
        );
        for format in ckmg::DeviceFormat::ALL {
            if !matches!(
                format,
                ckmg::DeviceFormat::DeviceJoin | ckmg::DeviceFormat::DeviceSession
            ) {
                assert!(pending.sign_device(format, payload).is_err());
            }
        }
        let signed = [ckmg::DeviceFormat::DeviceSession.tag(), &payload[..]].concat();
        ckmg::verify_ed25519(device.value(), &signed, &session).unwrap();
        // Activation keeps the device key as the authority reference and the time.
        let mut owner = DeviceOwner {
            device,
            seed: commitment,
        };
        let accepted = pending
            .activate(&mut TestClock(30), &mut ckmg::SystemEntropy, &mut owner)
            .await
            .unwrap();
        assert_eq!(accepted.phase().unwrap(), InitialPhase::Pending);
        assert_eq!(accepted.genesis_at().unwrap(), 20);
        assert_eq!(accepted.receipt().passkey_challenge().unwrap(), challenge);
        assert_eq!(
            cchr::lineage_genesis_action(accepted.receipt(), salt, 20).unwrap(),
            cchr::lineage_genesis_action_for(challenge, salt, 20).unwrap()
        );
        drop(accepted);
        let reopened = opening(9, "garden")
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.genesis_at().unwrap(), 20);
        assert_eq!(destination.writes.get(), 2);
    }
);

shared!(
    passkey_enrollment_has_no_genesis_time_and_no_device_signer,
    {
        let destination = Destination::new();
        let seed = ckmg::EnrollmentSeed::new(
            ckmg::Binding::new("garden", "member").unwrap(),
            &mut ckmg::SystemEntropy,
        )
        .unwrap();
        let pending = opening(9, "garden")
            .retain_enrollment(
                destination.clone(),
                seed,
                ckmg::DeviceInfo::new("fixture", b"credential").unwrap(),
                b"finish",
                &mut TestClock(20),
                &mut ckmg::SystemEntropy,
            )
            .await
            .unwrap();
        assert_eq!(pending.finish_continuation().unwrap(), b"finish");
        assert_eq!(pending.genesis_at(), Err(InitialError::Invalid));
        assert_eq!(
            pending.lineage_genesis_action([5; 32]).err(),
            Some(InitialError::Invalid)
        );
        assert_eq!(
            pending.sign_device(ckmg::DeviceFormat::DeviceSession, b"nonce"),
            Err(InitialError::Invalid)
        );
    }
);

shared!(
    enrollment_continuation_is_exactly_one_finish_or_one_genesis_time,
    {
        let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf, "garden").unwrap();
        let candidate = &b"candidate"[..];
        let at = 20u64.to_le_bytes();
        let cases: [(&[(&[u8], &[u8])], bool); 8] = [
            (&[], true),
            (
                &[(ENROLLMENT, candidate), (ENROLLMENT_FINISH, b"finish")],
                true,
            ),
            (
                &[(ENROLLMENT, candidate), (ENROLLMENT_GENESIS_AT, &at)],
                true,
            ),
            (&[(ENROLLMENT, candidate)], false),
            (&[(ENROLLMENT_GENESIS_AT, &at)], false),
            (
                &[
                    (ENROLLMENT, candidate),
                    (ENROLLMENT_FINISH, b"finish"),
                    (ENROLLMENT_GENESIS_AT, &at),
                ],
                false,
            ),
            (&[(ENROLLMENT, candidate), (ENROLLMENT_FINISH, b"")], false),
            (
                &[(ENROLLMENT, candidate), (ENROLLMENT_GENESIS_AT, &at[..7])],
                false,
            ),
        ];
        for (puts, valid) in cases {
            let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
                .await
                .unwrap();
            if !puts.is_empty() {
                let changes: Vec<_> = puts
                    .iter()
                    .map(|(key, value)| cwst::Change::Put {
                        owner: OWNER,
                        key,
                        value,
                    })
                    .collect();
                store.commit(0, [1; 32], &changes, &[]).await.unwrap();
            }
            assert_eq!(enrollment_kind(&store).is_ok(), valid);
        }
    }
);

#[path = "initial_ack_provenance.rs"]
mod acknowledged_provenance_tests;

#[cfg(feature = "wallet")]
#[path = "initial_wallet_ack.rs"]
mod wallet_ack_tests;

#[cfg(feature = "wallet")]
#[path = "initial_account_ack.rs"]
mod account_ack_tests;
