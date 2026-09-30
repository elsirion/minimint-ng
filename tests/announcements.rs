use minimint_ng::{
    api::announcements::*,
    codec::text::hex_encode,
    config::{self, CanonicalUrl, Endpoint},
    crypto::secp::SecretKey,
    protocol::PeerId,
    storage::{Namespace, Store},
};
use sonic_rs::json;
use std::collections::BTreeMap;
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn secret(id: u8) -> SecretKey {
    SecretKey::from_bytes(&[id + 1; 32]).unwrap()
}
fn api(store: &Store) -> AnnouncementApi {
    AnnouncementApi::new(
        store.clone(),
        (0..4)
            .map(|id| (PeerId(id), secret(id as u8).public_key()))
            .collect(),
        PeerId(0),
        secret(0),
    )
    .unwrap()
}
fn url(text: &str) -> CanonicalUrl {
    CanonicalUrl::simple(text).unwrap()
}
fn announcement(api: &AnnouncementApi, nonce: u64, address: &str) -> SignedAnnouncement {
    api.sign_announcement(ApiAnnouncement {
        api_url: url(address),
        nonce,
    })
    .unwrap()
}
fn content(time: u64) -> String {
    format!(
        "{{\"api_urls\":[\"wss://example.com/\"],\"pkarr_id_z32\":\"key\",\"timestamp_secs\":{time}}}"
    )
}
fn metadata(text: String) -> SignedMetadata {
    let signature = secret(0)
        .schnorr_sign(&config::guardian_metadata_digest(&text))
        .unwrap();
    SignedMetadata {
        content: text,
        signature,
    }
}
#[test]
fn independent_literal_domains_and_exact_original_json_bytes() {
    let value = ApiAnnouncement {
        api_url: url("wss://example.com/"),
        nonce: 253,
    };
    assert_eq!(
        hex_encode(&value.digest()),
        "36487e2467ac3f42c36a4aeb056b6df32da4284c53951399e51ac202d5cc0342"
    );
    let original = content(1);
    assert_eq!(
        hex_encode(&config::guardian_metadata_digest(&original)),
        "e3463fac9b3d5c9bebaa063e8c82d22ed8140b153ba3f94e586ae7829f661271"
    );
    let changed = original.replace(":[", ": [");
    assert_eq!(
        GuardianMetadata::parse(&original).unwrap(),
        GuardianMetadata::parse(&changed).unwrap()
    );
    assert_ne!(
        config::guardian_metadata_digest(&original),
        config::guardian_metadata_digest(&changed)
    );
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    let mut signed = metadata(original);
    signed.content = changed;
    assert!(matches!(
        api.submit_metadata(PeerId(0), &signed, 1),
        Err(AnnouncementError::InvalidSignature)
    ));
    assert!(api.metadata(&store.snapshot().unwrap()).unwrap().is_empty());
}
#[test]
fn announcement_native_rpc_nonce_checks_and_identity_map_immutability() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    let original = url("wss://example.com/");
    let configured = BTreeMap::from([(
        PeerId(0),
        Endpoint {
            url: original.clone(),
            name: "Guardian".into(),
        },
    )]);
    let id = config::federation_id(&configured);
    assert_eq!(
        api.dispatch("api_announcements", &json!(null), 0).unwrap(),
        json!({})
    );
    assert_eq!(
        api.operational_api_url(&store.snapshot().unwrap(), PeerId(0), &original)
            .unwrap(),
        original
    );
    let signed = announcement(&api, 0, "wss://override.example.com/");
    let params = json!({"peer_id":0,"api_announcement":signed.api_announcement.json(),"signature":hex_encode(&signed.signature)});
    assert_eq!(
        api.dispatch("submit_api_announcement", &params, 0).unwrap(),
        json!(null)
    );
    assert_eq!(
        api.dispatch("api_announcements", &json!(null), 0).unwrap(),
        json!({"0":signed.json()})
    );
    assert_eq!(
        api.operational_api_url(&store.snapshot().unwrap(), PeerId(0), &original)
            .unwrap(),
        signed.api_announcement.api_url
    );
    assert_eq!(config::federation_id(&configured), id);
    let before = store
        .snapshot()
        .unwrap()
        .scan_prefix(Namespace::Local, b"")
        .unwrap();
    api.submit_announcement(PeerId(0), &signed).unwrap();
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Local, b"")
            .unwrap(),
        before
    );
    assert!(matches!(
        api.submit_announcement(
            PeerId(0),
            &announcement(&api, 0, "wss://different.example.com/")
        ),
        Err(AnnouncementError::NonceNotIncreasing)
    ));
    api.submit_announcement(
        PeerId(0),
        &announcement(&api, u64::MAX, "wss://latest.example.com/"),
    )
    .unwrap();
    assert!(matches!(
        api.submit_announcement(PeerId(0), &signed),
        Err(AnnouncementError::NonceNotIncreasing)
    ));
    assert!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Replicated, b"")
            .unwrap()
            .is_empty()
    );
}
#[test]
fn metadata_future_bound_is_inclusive_saturating_and_old_data_has_no_age_rejection() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    api.submit_metadata(PeerId(0), &metadata(content(0)), u64::MAX)
        .unwrap();
    api.submit_metadata(PeerId(0), &metadata(content(3610)), 10)
        .unwrap();
    assert!(matches!(
        api.submit_metadata(PeerId(0), &metadata(content(3611)), 10),
        Err(AnnouncementError::TimestampTooFarAhead)
    ));
    api.submit_metadata(PeerId(0), &metadata(content(u64::MAX)), u64::MAX - 1)
        .unwrap();
    assert_eq!(
        GuardianMetadata::parse(
            &api.metadata(&store.snapshot().unwrap()).unwrap()[&PeerId(0)].content
        )
        .unwrap()
        .timestamp_secs,
        u64::MAX
    );
}
#[test]
fn metadata_idempotence_uses_bytes_and_replacement_requires_strictly_later_time() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    let signed = api.sign_metadata(content(10), 10).unwrap();
    let params =
        json!({"peer_id":0,"content":signed.content,"signature":hex_encode(&signed.signature)});
    assert_eq!(
        api.dispatch("submit_guardian_metadata", &params, 10)
            .unwrap(),
        json!(null)
    );
    let before = store
        .snapshot()
        .unwrap()
        .scan_prefix(Namespace::Local, b"")
        .unwrap();
    api.submit_metadata(PeerId(0), &signed, 10).unwrap();
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Local, b"")
            .unwrap(),
        before
    );
    let reordered = metadata(
        "{\"timestamp_secs\":10,\"pkarr_id_z32\":\"key\",\"api_urls\":[\"wss://example.com/\"]}"
            .into(),
    );
    assert!(matches!(
        api.submit_metadata(PeerId(0), &reordered, 10),
        Err(AnnouncementError::TimestampNotIncreasing)
    ));
    api.submit_metadata(PeerId(0), &metadata(content(11)), 11)
        .unwrap();
    assert!(matches!(
        api.submit_metadata(PeerId(0), &signed, 11),
        Err(AnnouncementError::TimestampNotIncreasing)
    ));
    assert_eq!(
        api.dispatch("guardian_metadata", &json!(null), 11).unwrap(),
        json!({"0":metadata(content(11)).json()})
    );
}
#[test]
fn invalid_keys_signatures_and_parsed_content_leave_local_records_unchanged() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    let signed = announcement(&api, 0, "wss://example.com/");
    assert!(matches!(
        api.submit_announcement(PeerId(9), &signed),
        Err(AnnouncementError::UnknownPeer)
    ));
    assert!(matches!(
        api.submit_announcement(PeerId(1), &signed),
        Err(AnnouncementError::InvalidSignature)
    ));
    let mut invalid = signed;
    invalid.signature[0] ^= 1;
    assert!(matches!(
        api.submit_announcement(PeerId(0), &invalid),
        Err(AnnouncementError::InvalidSignature)
    ));
    for text in [
        "null",
        "{}",
        "{\"api_urls\":[],\"pkarr_id_z32\":\"k\",\"timestamp_secs\":-1}",
        "{\"api_urls\":[],\"pkarr_id_z32\":\"k\",\"timestamp_secs\":1,\"timestamp_secs\":2}",
        "{\"api_urls\":[],\"pkarr_id_z32\":\"k\",\"timestamp_secs\":1,\"iroh_next_endpoint\":false}",
    ] {
        assert!(matches!(
            api.submit_metadata(PeerId(0), &metadata(text.into()), 10),
            Err(AnnouncementError::InvalidParams)
        ));
    }
    assert!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Local, b"")
            .unwrap()
            .is_empty()
    );
    let bad = AnnouncementApi::new(
        store,
        BTreeMap::from([(PeerId(0), secret(1).public_key())]),
        PeerId(0),
        secret(0),
    );
    assert!(matches!(bad, Err(AnnouncementError::InvalidConfiguration)));
}
#[test]
fn metadata_optional_endpoint_unknown_fields_and_fullwidth_time_are_preserved() {
    let original = " {\"api_urls\":[],\"pkarr_id_z32\":\"arbitrary string\",\"timestamp_secs\":18446744073709551615,\"iroh_next_endpoint\":\"endpoint\",\"extra\":true} ";
    let parsed = GuardianMetadata::parse(original).unwrap();
    assert_eq!(parsed.timestamp_secs, u64::MAX);
    assert_eq!(parsed.iroh_next_endpoint.as_deref(), Some("endpoint"));
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    let signed = api.sign_metadata(original.into(), u64::MAX).unwrap();
    api.submit_metadata(PeerId(0), &signed, u64::MAX).unwrap();
    assert_eq!(
        api.metadata(&store.snapshot().unwrap()).unwrap()[&PeerId(0)].content,
        original
    );
}
#[test]
fn both_signed_record_types_reopen_and_invalid_stored_signature_is_detected() {
    let dir = fixture::TestDir::new();
    {
        let store = Store::open(dir.path()).unwrap();
        let api = api(&store);
        api.submit_announcement(PeerId(0), &announcement(&api, 5, "wss://example.com/"))
            .unwrap();
        api.submit_metadata(PeerId(0), &metadata(content(6)), 6)
            .unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    assert_eq!(
        api.announcements(&store.snapshot().unwrap()).unwrap()[&PeerId(0)]
            .api_announcement
            .nonce,
        5
    );
    assert_eq!(
        api.metadata(&store.snapshot().unwrap()).unwrap()[&PeerId(0)].content,
        content(6)
    );
    let key = b"api-announcement/v1/\x00\x00";
    let mut bytes = store
        .snapshot()
        .unwrap()
        .get(Namespace::Local, key)
        .unwrap()
        .unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let mut writer = store.transaction().unwrap();
    writer.put(Namespace::Local, key, &bytes).unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        api.announcements(&store.snapshot().unwrap()),
        Err(AnnouncementError::CorruptState)
    ));
}
#[test]
fn undocumented_admin_json_shapes_are_not_guessed() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let api = api(&store);
    for method in ["sign_api_announcement", "sign_guardian_metadata"] {
        assert!(matches!(
            api.dispatch(method, &json!(null), 0),
            Err(AnnouncementError::SchemaUnavailable)
        ));
    }
    assert!(matches!(
        api.dispatch("api_announcements", &json!([]), 0),
        Err(AnnouncementError::InvalidParams)
    ));
    assert!(matches!(
        api.dispatch("submit_api_announcement", &json!({"peer_id":65536}), 0),
        Err(AnnouncementError::InvalidParams)
    ));
}
