//! API-001 JSON-RPC envelope validation, independent of endpoint execution.
use crate::json;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json as value};
use zeroize::Zeroizing;
/// Local API resource policy; not a consensus constant.
pub const MAX_BATCH_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcError {
    pub code: i32,
    pub message: &'static str,
}
impl RpcError {
    pub const PARSE: Self = Self {
        code: -32700,
        message: "Parse error",
    };
    pub const REQUEST: Self = Self {
        code: -32600,
        message: "Invalid Request",
    };
    pub const PARAMS: Self = Self {
        code: -32602,
        message: "Invalid params",
    };
    pub const UNAUTHORIZED: Self = Self {
        code: 401,
        message: "Invalid administrator authorization",
    };
    pub const METHOD: Self = Self {
        code: -32601,
        message: "Method not found",
    };
    pub const INTERNAL: Self = Self {
        code: 500,
        message: "Server error",
    };
}
// Request parameters can contain backups or secrets; no derived diagnostics.
pub struct Request {
    pub id: Option<Value>,
    pub method: String,
    auth: Option<Zeroizing<String>>,
    pub params: Value,
}
impl Request {
    /// A request without JSON-RPC identifier, as carried by an Iroh API stream
    /// (API-002). The caller has already validated its envelope.
    pub(crate) fn new(method: String, auth: Option<Zeroizing<String>>, params: Value) -> Self {
        Self {
            id: None,
            method,
            auth,
            params,
        }
    }
    /// Transport authentication never supplies administrator authorization.
    pub fn require_admin(&self, expected: &str) -> Result<(), RpcError> {
        let supplied = self
            .auth
            .as_deref()
            .map(|s| s.as_bytes())
            .unwrap_or_default();
        if expected.is_empty()
            || supplied.len() != expected.len()
            || !openssl::memcmp::eq(supplied, expected.as_bytes())
        {
            Err(RpcError::UNAUTHORIZED)
        } else {
            Ok(())
        }
    }
    pub fn response(&self, result: Result<Value, RpcError>) -> Option<Value> {
        self.id.as_ref().map(|id| response(id.clone(), result))
    }
}
pub struct Failure {
    pub id: Value,
    pub error: RpcError,
    reply: bool,
}
impl Failure {
    pub fn response(self) -> Option<Value> {
        self.reply.then(|| response(self.id, Err(self.error)))
    }
}
pub fn response(id: Value, result: Result<Value, RpcError>) -> Value {
    match result {
        Ok(result) => value!({"jsonrpc":"2.0","id":id,"result":result}),
        Err(error) => {
            value!({"jsonrpc":"2.0","id":id,"error":{"code":error.code,"message":error.message}})
        }
    }
}
fn request(value: &Value) -> Result<Request, Failure> {
    let invalid = || Failure {
        id: value!(null),
        error: RpcError::REQUEST,
        reply: true,
    };
    if !value.is_object() || value.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(invalid());
    }
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(invalid)?;
    let id = value.get("id").cloned();
    if id
        .as_ref()
        .is_some_and(|v| !(v.is_null() || v.is_str() || v.is_number()))
    {
        return Err(invalid());
    }
    if value
        .get("params")
        .is_some_and(|v| !(v.is_array() || v.is_object()))
    {
        return Err(invalid());
    }
    let bad_params = || Failure {
        id: id.clone().unwrap_or_else(|| value!(null)),
        error: RpcError::PARAMS,
        reply: id.is_some(),
    };
    let outer = value
        .get("params")
        .and_then(|v| v.as_array())
        .filter(|a| a.len() == 1)
        .ok_or_else(bad_params)?;
    let envelope = &outer[0];
    if !envelope.is_object() {
        return Err(bad_params());
    }
    let auth = match envelope.get("auth") {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => Some(Zeroizing::new(
            v.as_str().ok_or_else(bad_params)?.to_owned(),
        )),
    };
    let params = envelope.get("params").cloned().ok_or_else(bad_params)?;
    Ok(Request {
        id,
        method: method.to_owned(),
        auth,
        params,
    })
}
/// One parsed message is either a request or a JSON-RPC batch. Limits apply to
/// the whole incoming message; endpoint-specific limits still apply afterward.
/// Empty batches produce one Invalid Request response, not an empty response.
pub struct Message {
    pub batch: bool,
    pub requests: Vec<Result<Request, Failure>>,
}
pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Message, Failure> {
    let value = json::parse(bytes, maximum_bytes, 64).map_err(|_| Failure {
        id: value!(null),
        error: RpcError::PARSE,
        reply: true,
    })?;
    if let Some(array) = value.as_array() {
        if array.is_empty() {
            return Err(Failure {
                id: value!(null),
                error: RpcError::REQUEST,
                reply: true,
            });
        }
        if array.len() > MAX_BATCH_ITEMS {
            return Err(Failure {
                id: value!(null),
                error: RpcError {
                    code: -32000,
                    message: "Batch limit exceeded",
                },
                reply: true,
            });
        }
        Ok(Message {
            batch: true,
            requests: array.iter().map(request).collect(),
        })
    } else {
        Ok(Message {
            batch: false,
            requests: vec![request(&value)],
        })
    }
}
