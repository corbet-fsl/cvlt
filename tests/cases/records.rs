//! Actual offline Mesh/Core record persistence. No accepting runtime or Authority.
use super::existing::{passkeys, unlock};
use cdht::runtime::Publication;
use cvlt::{PasskeyRecords, PreparedOpen, RecordError, Records, RestoreLookup};
use cwst::backend::{Backend, Memory};
use std::{num::NonZeroUsize, time::Duration};

#[tokio::test]
async fn retained_encrypted_bytes_reopen_but_offline_cache_is_not_fresh_authority() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = cmsh::VeilidConfig::new(
        "vault_record_test",
        "records",
        "org",
        Some(directory.path().to_str().unwrap()),
        None,
    );
    config.protected_store.always_use_insecure_storage = true;
    config.network.routing_table.bootstrap.clear();
    config.network.routing_table.bootstrap_keys.clear();
    let runtime = cmsh::VeilidRuntime::prepare(
        config,
        cmsh::VeilidLimits {
            queued_messages: NonZeroUsize::new(8).unwrap(),
            listeners: NonZeroUsize::new(2).unwrap(),
            deadline: Duration::from_millis(100),
        },
    )
    .await
    .unwrap();
    let records = runtime.records(NonZeroUsize::new(3).unwrap()).unwrap();
    let mut client = passkeys().await;
    let prepared = PreparedOpen::new(unlock(&mut client).await, "garden").unwrap();
    let locator = prepared.locator();
    let lookup = prepared.native_records(&records).await.unwrap();
    assert_eq!(format!("{lookup:?}"), "PasskeyRecords([redacted])");
    let record = lookup.into_record();
    let key = record.identity().key;
    let owner = record.identity().owner;

    // Payload is the original encrypted Storage fixture, deliberately NOT a Keys
    // checkpoint or compound restore format. Only actual opaque record custody is tested.
    let prf = unlock(&mut client)
        .await
        .import(ckmg::passkey::PrfOutput::from_bytes)
        .unwrap();
    let cipher = ckmg::passkey::store_cipher(&prf, "garden").unwrap();
    let backend = Memory::new();
    drop(
        cwst::Store::create(backend.clone(), &cipher, "garden")
            .await
            .unwrap(),
    );
    let encrypted = backend.read().await.unwrap().unwrap();
    let mut retained = PasskeyRecords::new(locator, record).unwrap();
    assert!(matches!(
        retained.publish(7, &encrypted).await.unwrap(),
        Publication::Queued
    ));
    assert!(matches!(
        retained
            .publish(7, b"altered wrapped checkpoint")
            .await
            .unwrap(),
        Publication::Conflict(_)
    ));
    assert!(matches!(
        retained.publish(6, &encrypted).await,
        Err(RecordError::Invalid)
    ));
    retained.close().await.unwrap();

    let mut reopened = prepared.native_records(&records).await.unwrap();
    // The original force=true core path must refuse before any cached response
    // when no DHT is online. A local value is not a network freshness witness.
    assert_eq!(
        reopened.checkpoint(&locator).await.unwrap_err(),
        RecordError::Unavailable
    );
    assert!(matches!(
        reopened.lookup(&locator).await,
        RestoreLookup::Unavailable
    ));
    let other = PreparedOpen::new(unlock(&mut client).await, "other").unwrap();
    assert_eq!(
        reopened.checkpoint(&other.locator()).await.unwrap_err(),
        RecordError::Invalid
    );
    assert!(matches!(
        reopened.lookup(&other.locator()).await,
        RestoreLookup::Unavailable
    ));
    let record = reopened.into_record();
    assert_eq!(record.identity().key, key);
    let retained = record.get(0, false).await.unwrap().unwrap();
    assert_eq!(retained.seq, 7);
    assert_eq!(retained.writer, owner);
    // Decode the exact existing owner framing through the maintained libraries.
    // No alternative decoder, raw root format or accepted Keys state is asserted.
    let compressed = cprz_pad::unpad(&retained.data).unwrap();
    let framed = cprz::portable::decompress(
        &compressed,
        cdht::MAX_SUBKEY_SIZE,
        ckmg::MAX_CHECKPOINT_BYTES + b"cvlt.passkey-root.v1\0".len(),
    )
    .unwrap();
    assert_eq!(
        framed.strip_prefix(b"cvlt.passkey-root.v1\0").unwrap(),
        encrypted
    );
    record.into_backend().close().await.unwrap();

    let other_record = other.native_records(&records).await.unwrap().into_record();
    assert_ne!(other_record.identity().key, key);
    assert_ne!(other_record.identity().owner, owner);
    assert_eq!(
        other_record.get(0, false).await.unwrap_err(),
        cdht::Error::Unavailable
    );
    other_record.into_backend().close().await.unwrap();
    let mut unrelated_client = passkeys().await;
    let unrelated = PreparedOpen::new(unlock(&mut unrelated_client).await, "garden").unwrap();
    let unrelated_record = unrelated
        .native_records(&records)
        .await
        .unwrap()
        .into_record();
    assert_ne!(unrelated_record.identity().key, key);
    unrelated_record.into_backend().close().await.unwrap();

    let mut retained = prepared.native_records(&records).await.unwrap();
    assert!(matches!(
        retained.publish(7, &encrypted).await.unwrap(),
        Publication::Queued
    ));
    // Preserve the original prepare→stage→attach contract: even a failed attach
    // permanently ends offline publication, with no fallback to local writes.
    assert!(runtime.attach().await.is_err());
    assert!(retained.publish(8, &encrypted).await.is_err());
    retained.close().await.unwrap();
    runtime.shutdown().await;
    assert!(matches!(
        prepared.native_records(&records).await,
        Err(cvlt::OpenError::Records(RecordError::Unavailable))
    ));
}
