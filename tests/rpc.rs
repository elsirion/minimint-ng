use minimint_ng::api::rpc::{RpcError, decode};
use sonic_rs::{JsonValueTrait, json};
fn parsed(bytes: &[u8]) -> minimint_ng::api::rpc::Request {
    decode(bytes, 4096)
        .ok()
        .unwrap()
        .requests
        .remove(0)
        .ok()
        .unwrap()
}
#[test]
fn spec_envelope_full_width_id_and_distinct_admin_auth() {
    let r=parsed(br#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"session_count","params":[{"auth":null,"params":null}]}"#);
    assert_eq!(r.method, "session_count");
    assert!(r.params.is_null());
    assert_eq!(
        r.require_admin("transport-secret"),
        Err(RpcError::UNAUTHORIZED)
    );
    let reply = r.response(Ok(json!(7))).unwrap();
    assert_eq!(minimint_ng::json::unsigned(&reply["id"]).unwrap(), u64::MAX);
    assert!(reply.get("error").is_none());
    let r=parsed(br#"{"jsonrpc":"2.0","id":"x","method":"shutdown","params":[{"auth":"admin-secret","params":null}]}"#);
    assert_eq!(r.require_admin("admin-secret"), Ok(()));
    assert_eq!(r.require_admin("admin-secreu"), Err(RpcError::UNAUTHORIZED));
    assert_eq!(r.require_admin(""), Err(RpcError::UNAUTHORIZED));
    assert_eq!(
        r.response(Err(RpcError::UNAUTHORIZED)).unwrap()["error"]["code"].as_i64(),
        Some(401)
    );
}
#[test]
fn notifications_batches_and_null_id_are_distinct() {
    let msg=decode(br#"[{"jsonrpc":"2.0","method":"version","params":[{"params":null}]},{"jsonrpc":"2.0","id":null,"method":"version","params":[{"auth":null,"params":null}]}]"#,4096).ok().unwrap();
    assert!(msg.batch);
    let mut entries = msg.requests.into_iter();
    assert!(
        entries
            .next()
            .unwrap()
            .ok()
            .unwrap()
            .response(Ok(json!(null)))
            .is_none()
    );
    assert!(
        entries
            .next()
            .unwrap()
            .ok()
            .unwrap()
            .response(Ok(json!(null)))
            .unwrap()["id"]
            .is_null()
    );
    assert_eq!(decode(b"[]", 4096).err().unwrap().error, RpcError::REQUEST);
}
#[test]
fn malformed_outer_and_endpoint_envelopes_preserve_error_boundary() {
    for bytes in [b"{bad".as_slice(), br#"{"id":1,"id":2}"#] {
        assert_eq!(decode(bytes, 4096).err().unwrap().error, RpcError::PARSE);
    }
    let msg = decode(
        br#"{"jsonrpc":"2.0","id":9,"method":"version","params":[null]}"#,
        4096,
    )
    .ok()
    .unwrap();
    let err = msg.requests.into_iter().next().unwrap().err().unwrap();
    assert_eq!(err.error, RpcError::PARAMS);
    assert_eq!(err.id.as_u64(), Some(9));
    let msg = decode(
        br#"{"jsonrpc":"1.0","id":9,"method":"version","params":[]}"#,
        4096,
    )
    .ok()
    .unwrap();
    let err = msg.requests.into_iter().next().unwrap().err().unwrap();
    assert_eq!(err.error, RpcError::REQUEST);
    assert!(err.id.is_null());
}
#[test]
fn invalid_notification_params_are_silent_but_invalid_request_is_not() {
    let mut message = decode(
        br#"{"jsonrpc":"2.0","method":"version","params":[null]}"#,
        4096,
    )
    .ok()
    .unwrap();
    assert!(
        message
            .requests
            .remove(0)
            .err()
            .unwrap()
            .response()
            .is_none()
    );
    let mut message = decode(
        br#"{"jsonrpc":"2.0","method":"version","params":false}"#,
        4096,
    )
    .ok()
    .unwrap();
    assert!(
        message
            .requests
            .remove(0)
            .err()
            .unwrap()
            .response()
            .is_some()
    );
}
#[test]
fn batch_limit_and_noninteger_ids_preserve_raw_values() {
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"version","params":[{"params":null}]}"#;
    let batch = format!("[{}]", vec![request; 257].join(","));
    assert_eq!(
        decode(batch.as_bytes(), batch.len())
            .err()
            .unwrap()
            .error
            .code,
        -32000
    );
    for id in ["-9", "1.25", "1e30"] {
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"version","params":[{{"params":null}}]}}"#
        );
        let request = parsed(text.as_bytes());
        let reply = request.response(Ok(json!(null))).unwrap();
        assert_eq!(sonic_rs::to_string(&reply["id"]).unwrap(), id);
    }
}
