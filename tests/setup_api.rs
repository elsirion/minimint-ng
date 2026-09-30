use minimint_ng::{
    api::{
        rpc::{Request, decode},
        setup::SetupApi,
    },
    config::{BitcoinNetwork, CanonicalUrl},
    setup::SetupState,
};
use sonic_rs::{JsonValueTrait, Value, json};
use zeroize::Zeroizing;
fn request(method: &str, auth: Value, params: Value) -> Request {
    let text = sonic_rs::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":method,"params":[{"auth":auth,"params":params}]}),
    )
    .unwrap();
    decode(&text, 65536)
        .ok()
        .unwrap()
        .requests
        .remove(0)
        .ok()
        .unwrap()
}
fn setup() -> (
    SetupApi,
    std::sync::mpsc::Receiver<minimint_ng::api::setup::GenerationJob>,
) {
    let state = SetupState::new(
        CanonicalUrl::simple("ws://127.0.0.1:18100/").unwrap(),
        CanonicalUrl::simple("fedimint://127.0.0.1:18101/").unwrap(),
        BitcoinNetwork::Regtest,
        "0.13.0".into(),
    );
    SetupApi::new(state, Zeroizing::new("admin".into()))
        .ok()
        .unwrap()
}
#[test]
fn admin_required_parameters_idempotent_and_handoff_not_completion() {
    let (api, jobs) = setup();
    assert_eq!(
        api.dispatch(&request("setup_status", json!(null), json!(null)))
            .unwrap()
            .as_str(),
        Some("AwaitingLocalParams")
    );
    assert_eq!(
        api.dispatch(&request("get_setup_code", json!(null), json!(null)))
            .unwrap_err()
            .code,
        401
    );
    let params = json!({"name":"one","federation_name":"test","federation_size":1,"enabled_modules":["walletv2","mintv2","mintv2"]});
    let code = api
        .dispatch(&request("set_local_params", json!("admin"), params.clone()))
        .unwrap();
    assert_eq!(
        code.as_str(),
        api.dispatch(&request("set_local_params", json!("admin"), params))
            .unwrap()
            .as_str()
    );
    api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
        .unwrap();
    assert_eq!(
        api.dispatch(&request("setup_status", json!(null), json!(null)))
            .unwrap()
            .as_str(),
        Some("SharingConnectionCodes")
    );
    let job = jobs.try_recv().unwrap();
    assert_eq!(job.inputs.records.len(), 1);
    assert!(
        api.dispatch(&request(
            "reset_peer_setup_codes",
            json!("admin"),
            json!(null)
        ))
        .is_err()
    );
    assert!(
        api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
            .is_err()
    );
    assert!(jobs.try_recv().is_err());
    assert!(job.identity.private_key_der().is_ok());
}
#[test]
fn invalid_fields_and_failed_driver_handoff_leave_setup_retryable() {
    let (api, jobs) = setup();
    for params in [
        json!({"name":"one","network":"mainnet"}),
        json!({"name":"one","federation_size":4294967296u64}),
        json!({"name":"one","disable_base_fees":1}),
    ] {
        assert_eq!(
            api.dispatch(&request("set_local_params", json!("admin"), params))
                .unwrap_err()
                .code,
            400
        );
    }
    assert!(api.mark_running().is_err());
    api.dispatch(&request(
        "set_local_params",
        json!("admin"),
        json!({"name":"one","federation_name":"test","federation_size":1}),
    ))
    .unwrap();
    drop(jobs);
    assert_eq!(
        api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
            .unwrap_err()
            .code,
        500
    );
    api.dispatch(&request(
        "reset_peer_setup_codes",
        json!("admin"),
        json!(null),
    ))
    .unwrap();
}
#[test]
fn idempotent_parameter_and_peer_repeats_survive_driver_handoff() {
    let (api, jobs) = setup();
    let params = json!({"name":"one","federation_name":"test","federation_size":4});
    let local = api
        .dispatch(&request("set_local_params", json!("admin"), params.clone()))
        .unwrap();
    let mut codes = Vec::new();
    for i in 2..=4 {
        let mut peer = SetupState::new(
            CanonicalUrl::simple(&format!("ws://127.0.0.1:{}/", 18100 + i * 2)).unwrap(),
            CanonicalUrl::simple(&format!("fedimint://127.0.0.1:{}/", 18101 + i * 2)).unwrap(),
            BitcoinNetwork::Regtest,
            "0.13.0".into(),
        );
        let code = peer
            .set_local_params(minimint_ng::setup::LocalParams {
                name: format!("peer{i}"),
                federation_name: None,
                federation_size: None,
                enabled_modules: None,
                disable_base_fees: None,
            })
            .unwrap();
        api.dispatch(&request("add_peer_setup_code", json!("admin"), json!(code)))
            .unwrap();
        codes.push(code);
    }
    api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
        .unwrap();
    assert_eq!(jobs.try_recv().unwrap().inputs.records.len(), 4);
    assert_eq!(
        api.dispatch(&request("set_local_params", json!("admin"), params))
            .unwrap()
            .as_str(),
        local.as_str()
    );
    for (i, code) in codes.into_iter().enumerate() {
        assert_eq!(
            api.dispatch(&request("add_peer_setup_code", json!("admin"), json!(code)))
                .unwrap()
                .as_str(),
            Some(format!("peer{}", i + 2).as_str())
        );
    }
}

#[test]
fn authorized_setup_code_is_null_then_exact_string_and_rejects_nonnull_params() {
    let (api, jobs) = setup();
    let get = || {
        api.dispatch(&request("get_setup_code", json!("admin"), json!(null)))
            .unwrap()
    };
    assert_eq!(get(), json!(null));
    assert_eq!(
        api.dispatch(&request("get_setup_code", json!("admin"), json!([])))
            .unwrap_err()
            .code,
        400
    );
    let params = json!({"name":"one","federation_name":"test","federation_size":4,"disable_base_fees":false,"enabled_modules":["walletv2","mintv2"]});
    let code = api
        .dispatch(&request("set_local_params", json!("admin"), params.clone()))
        .unwrap();
    assert!(code.as_str().is_some());
    assert_eq!(get(), code);
    for auth in [json!(null), json!("wrong")] {
        assert_eq!(
            api.dispatch(&request("get_setup_code", auth, json!(null)))
                .unwrap_err()
                .code,
            401
        );
        assert_eq!(get(), code);
    }
    assert_eq!(
        api.dispatch(&request("set_local_params", json!("admin"), params))
            .unwrap(),
        code
    );
    assert!(jobs.try_recv().is_err());
}

fn peer_codes() -> Vec<String> {
    (2..=4)
        .map(|id| {
            let mut peer = SetupState::new(
                CanonicalUrl::simple(&format!("ws://127.0.0.1:{}/", 18200 + id * 2)).unwrap(),
                CanonicalUrl::simple(&format!("fedimint://127.0.0.1:{}/", 18201 + id * 2)).unwrap(),
                BitcoinNetwork::Regtest,
                "0.13.0".into(),
            );
            peer.set_local_params(minimint_ng::setup::LocalParams {
                name: format!("peer{id}"),
                federation_name: None,
                disable_base_fees: None,
                enabled_modules: None,
                federation_size: None,
            })
            .unwrap()
        })
        .collect()
}

#[test]
fn successful_native_reset_preserves_local_identity_params_and_allows_peer_retry() {
    // Capture the original private identity before moving state behind the
    // public handler. Secret comparisons intentionally omit debug values.
    let mut state = SetupState::new(
        CanonicalUrl::simple("ws://127.0.0.1:18100/").unwrap(),
        CanonicalUrl::simple("fedimint://127.0.0.1:18101/").unwrap(),
        BitcoinNetwork::Regtest,
        "0.13.0".into(),
    );
    let initial_code = state
        .set_local_params(minimint_ng::setup::LocalParams {
            name: "one".into(),
            federation_name: Some("test".into()),
            disable_base_fees: Some(false),
            federation_size: Some(4),
            enabled_modules: Some(["mintv2".into(), "walletv2".into()].into_iter().collect()),
        })
        .unwrap();
    let private = Zeroizing::new(state.identity().unwrap().private_key_der().unwrap());
    let certificate = state.identity().unwrap().certificate_der().unwrap();
    let expected = minimint_ng::config::SetupRecord::from_code(&initial_code).unwrap();
    let (api, jobs) = SetupApi::new(state, Zeroizing::new("admin".into()))
        .ok()
        .unwrap();
    let codes = peer_codes();
    for code in &codes {
        api.dispatch(&request("add_peer_setup_code", json!("admin"), json!(code)))
            .unwrap();
    }
    // A malformed reset is rejected; successful reset has literal JSON null.
    assert_eq!(
        api.dispatch(&request(
            "reset_peer_setup_codes",
            json!("admin"),
            json!({})
        ))
        .unwrap_err()
        .code,
        400
    );
    assert_eq!(
        api.dispatch(&request(
            "reset_peer_setup_codes",
            json!("admin"),
            json!(null)
        ))
        .unwrap(),
        json!(null)
    );
    assert_eq!(
        api.dispatch(&request("get_setup_code", json!("admin"), json!(null)))
            .unwrap(),
        json!(initial_code)
    );
    assert_eq!(
        api.dispatch(&request("setup_status", json!(null), json!(null)))
            .unwrap(),
        json!("SharingConnectionCodes")
    );
    // Losing imported peers makes size4 setup incomplete; no job is dispatched.
    assert_eq!(
        api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
            .unwrap_err()
            .code,
        500
    );
    assert!(jobs.try_recv().is_err());
    let params = json!({"name":"one","federation_name":"test","federation_size":4,"disable_base_fees":false,"enabled_modules":["walletv2","mintv2","mintv2"]});
    assert_eq!(
        api.dispatch(&request("set_local_params", json!("admin"), params))
            .unwrap(),
        json!(initial_code)
    );
    for (index, code) in codes.iter().enumerate() {
        assert_eq!(
            api.dispatch(&request("add_peer_setup_code", json!("admin"), json!(code)))
                .unwrap(),
            json!(format!("peer{}", index + 2))
        );
    }
    assert_eq!(
        api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
            .unwrap(),
        json!(null)
    );
    let job = jobs.try_recv().unwrap();
    assert_eq!(job.inputs.records.len(), 4);
    assert_eq!(job.inputs.records[&job.inputs.peer], expected);
    assert!(
        job.identity.private_key_der().unwrap().as_slice() == private.as_slice(),
        "reset changed local private identity"
    );
    assert_eq!(job.identity.certificate_der().unwrap(), certificate);
}

#[test]
fn admin_denials_preserve_imports_and_running_setup_mutations_are_unregistered() {
    let (api, jobs) = setup();
    let params = json!({"name":"one","federation_name":"test","federation_size":4});
    let local = api
        .dispatch(&request("set_local_params", json!("admin"), params.clone()))
        .unwrap();
    let codes = peer_codes();
    for code in &codes {
        api.dispatch(&request("add_peer_setup_code", json!("admin"), json!(code)))
            .unwrap();
    }
    for auth in [json!(null), json!("wrong")] {
        for (method, value) in [
            ("get_setup_code", json!(null)),
            ("reset_peer_setup_codes", json!(null)),
            ("set_local_params", json!({"name":"changed"})),
            ("add_peer_setup_code", json!("invalid")),
            ("start_dkg", json!(null)),
        ] {
            assert_eq!(
                api.dispatch(&request(method, auth.clone(), value))
                    .unwrap_err()
                    .code,
                401
            );
        }
    }
    assert_eq!(
        api.dispatch(&request("get_setup_code", json!("admin"), json!(null)))
            .unwrap(),
        local
    );
    assert!(jobs.try_recv().is_err());
    assert_eq!(
        api.dispatch(&request("start_dkg", json!("admin"), json!(null)))
            .unwrap(),
        json!(null)
    );
    let job = jobs.try_recv().unwrap();
    assert_eq!(
        job.inputs.records.len(),
        4,
        "unauthorized reset must retain every imported peer"
    );
    for code in &codes {
        let record = minimint_ng::config::SetupRecord::from_code(code).unwrap();
        assert!(
            job.inputs
                .records
                .values()
                .any(|existing| *existing == record)
        );
    }
    // This marks the handler's running boundary; it is not a real DKG run.
    api.mark_running().unwrap();
    assert_eq!(
        api.dispatch(&request("setup_status", json!(null), json!(null)))
            .unwrap(),
        json!("ConsensusIsRunning")
    );
    for (method, value) in [
        ("get_setup_code", json!(null)),
        ("reset_peer_setup_codes", json!(null)),
        ("set_local_params", params),
        ("add_peer_setup_code", json!(&codes[0])),
        ("start_dkg", json!(null)),
    ] {
        assert_eq!(
            api.dispatch(&request(method, json!("admin"), value))
                .unwrap_err()
                .code,
            -32601
        );
    }
    assert!(jobs.try_recv().is_err());
}
