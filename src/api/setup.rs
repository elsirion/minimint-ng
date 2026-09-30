//! Authenticated setup API and one-shot handoff to the daemon's DKG driver.
use super::{
    rpc::{Request, RpcError},
    server::{CallContext, Handler},
};
use crate::{
    json,
    net::tls::Identity,
    setup::{GenerationInputs, LocalParams, SetupState},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json as value};
use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        mpsc::{self, Receiver, SyncSender},
    },
};
use zeroize::Zeroizing;

/// The driver owns this identity after a successful start handoff. Never log it.
pub struct GenerationJob {
    pub inputs: GenerationInputs,
    pub identity: Identity,
}
struct State {
    setup: SetupState,
    dispatched: bool,
    running: bool,
}
pub struct SetupApi {
    state: Mutex<State>,
    admin: Zeroizing<String>,
    generation: SyncSender<GenerationJob>,
}
const BAD: RpcError = RpcError {
    code: 400,
    message: "Invalid setup parameters",
};
const START: RpcError = RpcError {
    code: 500,
    message: "Cannot start federation generation",
};
fn optional<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.get(name).filter(|v| !v.is_null())
}
fn local_params(value: &Value) -> Result<LocalParams, RpcError> {
    if !value.is_object() || value.get("network").is_some() {
        return Err(BAD);
    }
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(BAD)?
        .to_owned();
    let federation_name = optional(value, "federation_name")
        .map(|v| v.as_str().map(str::to_owned).ok_or(BAD))
        .transpose()?;
    let disable_base_fees = optional(value, "disable_base_fees")
        .map(|v| v.as_bool().ok_or(BAD))
        .transpose()?;
    let federation_size = optional(value, "federation_size")
        .map(|v| {
            json::unsigned(v)
                .ok()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(BAD)
        })
        .transpose()?;
    let enabled_modules = optional(value, "enabled_modules")
        .map(|v| {
            v.as_array()
                .ok_or(BAD)?
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or(BAD))
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .transpose()?;
    Ok(LocalParams {
        name,
        federation_name,
        disable_base_fees,
        enabled_modules,
        federation_size,
    })
}
impl SetupApi {
    pub fn new(
        setup: SetupState,
        admin: Zeroizing<String>,
    ) -> Result<(Self, Receiver<GenerationJob>), RpcError> {
        if admin.is_empty() {
            return Err(RpcError::UNAUTHORIZED);
        }
        let (generation, receiver) = mpsc::sync_channel(1);
        Ok((
            Self {
                state: Mutex::new(State {
                    setup,
                    dispatched: false,
                    running: false,
                }),
                admin,
                generation,
            },
            receiver,
        ))
    }
    /// Called only after the driver has persisted generated configuration and
    /// successfully installed the running consensus service.
    pub fn mark_running(&self) -> Result<(), RpcError> {
        let mut state = self.state.lock().map_err(|_| RpcError::INTERNAL)?;
        if !state.dispatched {
            return Err(START);
        }
        state.running = true;
        Ok(())
    }
    pub fn dispatch(&self, request: &Request) -> Result<Value, RpcError> {
        let method = request.method.as_str();
        if !matches!(
            method,
            "setup_status"
                | "set_local_params"
                | "add_peer_setup_code"
                | "reset_peer_setup_codes"
                | "get_setup_code"
                | "start_dkg"
        ) {
            return Err(RpcError::METHOD);
        }
        if method != "setup_status" {
            request.require_admin(&self.admin)?;
        }
        let mut state = self.state.lock().map_err(|_| RpcError::INTERNAL)?;
        if method == "setup_status" {
            if !request.params.is_null() {
                return Err(BAD);
            }
            return Ok(value!(if state.running {
                "ConsensusIsRunning"
            } else {
                state.setup.status().as_str()
            }));
        }
        if state.running {
            return Err(RpcError::METHOD);
        }
        if matches!(
            method,
            "get_setup_code" | "reset_peer_setup_codes" | "start_dkg"
        ) && !request.params.is_null()
        {
            return Err(BAD);
        }
        if method == "get_setup_code" {
            return Ok(value!(state.setup.get_setup_code()));
        }
        // Freeze changes after handing the exact map/identity to the driver,
        // while retaining SET-002/003's explicitly idempotent repeats.
        if state.dispatched {
            return match method {
                "set_local_params" => Ok(value!(
                    state
                        .setup
                        .set_local_params(local_params(&request.params)?)
                        .map_err(|_| BAD)?
                )),
                "add_peer_setup_code" => {
                    let code = request.params.as_str().ok_or(BAD)?;
                    let record = crate::config::SetupRecord::from_code(code).map_err(|_| BAD)?;
                    let frozen = state.setup.generation_inputs().map_err(|_| START)?;
                    if frozen
                        .records
                        .iter()
                        .any(|(peer, existing)| *peer != frozen.peer && *existing == record)
                    {
                        Ok(value!(record.name))
                    } else {
                        Err(START)
                    }
                }
                _ => Err(START),
            };
        }
        match method {
            "set_local_params" => Ok(value!(
                state
                    .setup
                    .set_local_params(local_params(&request.params)?)
                    .map_err(|_| BAD)?
            )),
            "add_peer_setup_code" => Ok(value!(
                state
                    .setup
                    .add_peer_setup_code(request.params.as_str().ok_or(BAD)?)
                    .map_err(|_| BAD)?
            )),
            "reset_peer_setup_codes" => {
                state.setup.reset_peer_setup_codes();
                Ok(value!(null))
            }
            "start_dkg" => {
                let inputs = state.setup.generation_inputs().map_err(|_| START)?;
                let identity = state.setup.identity().ok_or(START)?;
                let certificate = identity.certificate_der().map_err(|_| START)?;
                let private = Zeroizing::new(identity.private_key_der().map_err(|_| START)?);
                let identity = Identity::from_der(&certificate, &private).map_err(|_| START)?;
                self.generation
                    .try_send(GenerationJob { inputs, identity })
                    .map_err(|_| START)?;
                state.dispatched = true;
                Ok(value!(null))
            }
            _ => Err(RpcError::METHOD),
        }
    }
}
impl Handler for SetupApi {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError> {
        if context.is_cancelled() {
            return Err(RpcError::INTERNAL);
        }
        self.dispatch(request)
    }
}
