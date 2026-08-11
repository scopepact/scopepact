//! MCP 2025-06-18 JSON-RPC validation and connection correlation.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::{GuardError, Result};

pub const SUPPORTED_PROTOCOL_VERSION: &str = "2025-06-18";
pub const MAX_PENDING_REQUESTS: usize = 1_024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_NODES: usize = 65_536;
pub const MAX_JSON_CONTAINER_ENTRIES: usize = 4_096;
pub const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;

const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RequestId {
    String(String),
    Number(i64),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ProgressToken {
    String(String),
    Number(i64),
}

#[derive(Clone, Debug)]
pub enum MessageClass {
    Request { id: Value, method: String },
    Notification { method: String },
    SuccessResponse { id: Value },
    ErrorResponse { id: Value },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardDisposition {
    Forward,
    RejectServerRequest { id: Value, method: String },
}

#[derive(Clone, Debug)]
struct PendingRequest {
    method: String,
    progress_token: Option<ProgressToken>,
    last_progress: Option<f64>,
}

#[derive(Clone, Debug)]
enum Lifecycle {
    Uninitialized,
    Initializing(RequestId),
    AwaitingInitialized,
    Active,
    Failed,
}

/// Correlation and lifecycle state shared by both stdio directions.
pub struct ConnectionTracker {
    client_pending: HashMap<RequestId, PendingRequest>,
    server_pending: HashMap<RequestId, PendingRequest>,
    lifecycle: Lifecycle,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self {
            client_pending: HashMap::new(),
            server_pending: HashMap::new(),
            lifecycle: Lifecycle::Uninitialized,
        }
    }
}

/// Validates bounded JSON structure and the base MCP JSON-RPC shape.
///
/// # Errors
///
/// Returns an error for batches, invalid JSON-RPC objects, unsafe IDs,
/// oversized strings or containers, or excessive nesting/node count.
pub fn classify_message(message: &Value) -> Result<MessageClass> {
    validate_structure(message)?;
    let object = message.as_object().ok_or_else(|| {
        GuardError::InvalidRequest(
            "MCP message must be one JSON object; batches are forbidden".into(),
        )
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(GuardError::InvalidRequest(
            "MCP message jsonrpc must be exactly \"2.0\"".into(),
        ));
    }
    if let Some(method) = object.get("method") {
        reject_unknown_fields(object, &["jsonrpc", "id", "method", "params"])?;
        let method = method
            .as_str()
            .filter(|method| valid_text(method, 256))
            .ok_or_else(|| GuardError::InvalidRequest("MCP method is invalid".into()))?;
        if object.contains_key("result") || object.contains_key("error") {
            return Err(GuardError::InvalidRequest(
                "MCP request or notification cannot contain result or error".into(),
            ));
        }
        if object
            .get("params")
            .is_some_and(|params| !params.is_object())
        {
            return Err(GuardError::InvalidRequest(
                "MCP params must be an object when present".into(),
            ));
        }
        return if let Some(id) = object.get("id") {
            parse_request_id(id)?;
            Ok(MessageClass::Request {
                id: id.clone(),
                method: method.to_owned(),
            })
        } else {
            Ok(MessageClass::Notification {
                method: method.to_owned(),
            })
        };
    }

    reject_unknown_fields(object, &["jsonrpc", "id", "result", "error"])?;
    let id = object
        .get("id")
        .ok_or_else(|| GuardError::InvalidRequest("MCP response requires an id".into()))?;
    parse_request_id(id)?;
    match (object.get("result"), object.get("error")) {
        (Some(result), None) if result.is_object() => {
            Ok(MessageClass::SuccessResponse { id: id.clone() })
        }
        (None, Some(error)) => {
            validate_error(error)?;
            Ok(MessageClass::ErrorResponse { id: id.clone() })
        }
        _ => Err(GuardError::InvalidRequest(
            "MCP response requires exactly one object result or valid error".into(),
        )),
    }
}

impl ConnectionTracker {
    /// Removes a request that the proxy answered without forwarding it.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is no longer pending.
    pub fn complete_locally(&mut self, direction: Direction, id: &Value) -> Result<()> {
        let id = parse_request_id(id)?;
        let pending = match direction {
            Direction::ClientToServer => &mut self.client_pending,
            Direction::ServerToClient => &mut self.server_pending,
        };
        pending.remove(&id).ok_or_else(|| {
            GuardError::InvalidRequest("locally completed MCP request is not pending".into())
        })?;
        Ok(())
    }

    /// Applies lifecycle, correlation, progress, cancellation, and pending
    /// request limits to one already-classified MCP message.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid lifecycle order, duplicate/unknown IDs,
    /// invalid progress/cancellation correlation, or pending request overflow.
    pub fn accept(
        &mut self,
        direction: Direction,
        message: &Value,
        class: &MessageClass,
    ) -> Result<ForwardDisposition> {
        match class {
            MessageClass::Request { id, method } => {
                self.accept_request(direction, message, id, method)
            }
            MessageClass::Notification { method } => {
                self.accept_notification(direction, message, method)
            }
            MessageClass::SuccessResponse { id } => {
                self.accept_response(direction, message, id, false)
            }
            MessageClass::ErrorResponse { id } => {
                self.accept_response(direction, message, id, true)
            }
        }
    }

    fn accept_request(
        &mut self,
        direction: Direction,
        message: &Value,
        id: &Value,
        method: &str,
    ) -> Result<ForwardDisposition> {
        let request_id = parse_request_id(id)?;
        match (&self.lifecycle, direction, method) {
            (Lifecycle::Uninitialized, Direction::ClientToServer, "initialize") => {
                validate_initialize_request(message)?;
            }
            (Lifecycle::Active, _, _) => {}
            _ => {
                return Err(GuardError::InvalidRequest(
                    "MCP request is not valid in the current connection lifecycle".into(),
                ));
            }
        }
        if direction == Direction::ServerToClient && method != "ping" {
            return Ok(ForwardDisposition::RejectServerRequest {
                id: id.clone(),
                method: method.to_owned(),
            });
        }
        let progress_token = request_progress_token(message)?;
        let pending = match direction {
            Direction::ClientToServer => &mut self.client_pending,
            Direction::ServerToClient => &mut self.server_pending,
        };
        if pending.len() >= MAX_PENDING_REQUESTS {
            return Err(GuardError::InvalidRequest(
                "MCP pending request limit is exhausted".into(),
            ));
        }
        if pending.contains_key(&request_id) {
            return Err(GuardError::InvalidRequest(
                "MCP request id is already pending in this direction".into(),
            ));
        }
        if progress_token.as_ref().is_some_and(|token| {
            pending
                .values()
                .any(|request| request.progress_token.as_ref() == Some(token))
        }) {
            return Err(GuardError::InvalidRequest(
                "MCP progress token is already active in this direction".into(),
            ));
        }
        pending.insert(
            request_id.clone(),
            PendingRequest {
                method: method.to_owned(),
                progress_token,
                last_progress: None,
            },
        );
        if method == "initialize" {
            self.lifecycle = Lifecycle::Initializing(request_id);
        }
        Ok(ForwardDisposition::Forward)
    }

    fn accept_notification(
        &mut self,
        direction: Direction,
        message: &Value,
        method: &str,
    ) -> Result<ForwardDisposition> {
        if method == "notifications/initialized" {
            if direction != Direction::ClientToServer
                || !matches!(self.lifecycle, Lifecycle::AwaitingInitialized)
            {
                return Err(GuardError::InvalidRequest(
                    "MCP initialized notification is out of order".into(),
                ));
            }
            self.lifecycle = Lifecycle::Active;
            return Ok(ForwardDisposition::Forward);
        }
        if !matches!(self.lifecycle, Lifecycle::Active) {
            return Err(GuardError::InvalidRequest(
                "MCP notification is not valid before initialization completes".into(),
            ));
        }
        match method {
            "notifications/cancelled" => self.validate_cancellation(direction, message)?,
            "notifications/progress" => self.validate_progress(direction, message)?,
            _ => {}
        }
        Ok(ForwardDisposition::Forward)
    }

    fn accept_response(
        &mut self,
        direction: Direction,
        message: &Value,
        id: &Value,
        is_error: bool,
    ) -> Result<ForwardDisposition> {
        let request_id = parse_request_id(id)?;
        let pending = match direction {
            Direction::ServerToClient => &mut self.client_pending,
            Direction::ClientToServer => &mut self.server_pending,
        };
        let request = pending.remove(&request_id).ok_or_else(|| {
            GuardError::InvalidRequest(
                "MCP response id does not match an active request in the opposite direction".into(),
            )
        })?;
        if request.method == "initialize" {
            if !matches!(self.lifecycle, Lifecycle::Initializing(ref id) if id == &request_id) {
                return Err(GuardError::InvalidRequest(
                    "MCP initialize response is out of order".into(),
                ));
            }
            if is_error {
                self.lifecycle = Lifecycle::Failed;
            } else {
                validate_initialize_response(message)?;
                self.lifecycle = Lifecycle::AwaitingInitialized;
            }
        } else if !matches!(self.lifecycle, Lifecycle::Active) {
            return Err(GuardError::InvalidRequest(
                "MCP response is not valid before initialization completes".into(),
            ));
        }
        Ok(ForwardDisposition::Forward)
    }

    fn validate_cancellation(&self, direction: Direction, message: &Value) -> Result<()> {
        let params = required_params(message, "cancelled notification")?;
        reject_unknown_fields(params, &["requestId", "reason", "_meta"])?;
        let id = params.get("requestId").ok_or_else(|| {
            GuardError::InvalidRequest("MCP cancellation requires requestId".into())
        })?;
        let id = parse_request_id(id)?;
        if params
            .get("reason")
            .is_some_and(|reason| !reason.as_str().is_some_and(|value| valid_text(value, 1024)))
        {
            return Err(GuardError::InvalidRequest(
                "MCP cancellation reason is invalid".into(),
            ));
        }
        let pending = match direction {
            Direction::ClientToServer => &self.client_pending,
            Direction::ServerToClient => &self.server_pending,
        };
        let request = pending.get(&id).ok_or_else(|| {
            GuardError::InvalidRequest("MCP cancellation references no active request".into())
        })?;
        if request.method == "initialize" {
            return Err(GuardError::InvalidRequest(
                "MCP initialize request cannot be cancelled".into(),
            ));
        }
        Ok(())
    }

    fn validate_progress(&mut self, direction: Direction, message: &Value) -> Result<()> {
        let params = required_params(message, "progress notification")?;
        reject_unknown_fields(
            params,
            &["progressToken", "progress", "total", "message", "_meta"],
        )?;
        let token = params.get("progressToken").ok_or_else(|| {
            GuardError::InvalidRequest("MCP progress requires progressToken".into())
        })?;
        let token = parse_progress_token(token)?;
        let progress = finite_number(params.get("progress"), "MCP progress value")?;
        if progress < 0.0 {
            return Err(GuardError::InvalidRequest(
                "MCP progress value cannot be negative".into(),
            ));
        }
        if let Some(total) = params.get("total") {
            if finite_number(Some(total), "MCP progress total")? < 0.0 {
                return Err(GuardError::InvalidRequest(
                    "MCP progress total cannot be negative".into(),
                ));
            }
        }
        if params.get("message").is_some_and(|message| {
            !message
                .as_str()
                .is_some_and(|value| valid_text(value, 4096))
        }) {
            return Err(GuardError::InvalidRequest(
                "MCP progress message is invalid".into(),
            ));
        }
        let pending = match direction {
            Direction::ServerToClient => &mut self.client_pending,
            Direction::ClientToServer => &mut self.server_pending,
        };
        let request = pending
            .values_mut()
            .find(|request| request.progress_token.as_ref() == Some(&token))
            .ok_or_else(|| GuardError::InvalidRequest("MCP progress token is not active".into()))?;
        if request
            .last_progress
            .is_some_and(|previous| progress <= previous)
        {
            return Err(GuardError::InvalidRequest(
                "MCP progress value must increase".into(),
            ));
        }
        request.last_progress = Some(progress);
        Ok(())
    }
}

fn validate_initialize_request(message: &Value) -> Result<()> {
    let params = required_params(message, "initialize request")?;
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| GuardError::InvalidRequest("initialize requires protocolVersion".into()))?;
    if version != SUPPORTED_PROTOCOL_VERSION {
        return Err(GuardError::InvalidRequest(format!(
            "unsupported MCP protocol version {version:?}; expected {SUPPORTED_PROTOCOL_VERSION}"
        )));
    }
    if !params.get("capabilities").is_some_and(Value::is_object)
        || !params.get("clientInfo").is_some_and(Value::is_object)
    {
        return Err(GuardError::InvalidRequest(
            "initialize requires object capabilities and clientInfo".into(),
        ));
    }
    Ok(())
}

fn validate_initialize_response(message: &Value) -> Result<()> {
    let result = message
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            GuardError::InvalidRequest("initialize response requires an object result".into())
        })?;
    if result.get("protocolVersion").and_then(Value::as_str) != Some(SUPPORTED_PROTOCOL_VERSION)
        || !result.get("capabilities").is_some_and(Value::is_object)
        || !result.get("serverInfo").is_some_and(Value::is_object)
    {
        return Err(GuardError::InvalidRequest(
            "initialize response has unsupported version or missing capability/server metadata"
                .into(),
        ));
    }
    Ok(())
}

fn validate_error(error: &Value) -> Result<()> {
    let error = error
        .as_object()
        .ok_or_else(|| GuardError::InvalidRequest("MCP error must be an object".into()))?;
    reject_unknown_fields(error, &["code", "message", "data"])?;
    let code = error
        .get("code")
        .and_then(Value::as_i64)
        .ok_or_else(|| GuardError::InvalidRequest("MCP error code must be an integer".into()))?;
    if i32::try_from(code).is_err()
        || !error
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| valid_text(message, 4096))
    {
        return Err(GuardError::InvalidRequest(
            "MCP error code or message is invalid".into(),
        ));
    }
    Ok(())
}

fn required_params<'a>(message: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    message
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| GuardError::InvalidRequest(format!("MCP {label} requires object params")))
}

fn request_progress_token(message: &Value) -> Result<Option<ProgressToken>> {
    message
        .pointer("/params/_meta/progressToken")
        .map(parse_progress_token)
        .transpose()
}

fn parse_request_id(value: &Value) -> Result<RequestId> {
    if let Some(value) = value.as_str().filter(|value| valid_text(value, 256)) {
        return Ok(RequestId::String(value.to_owned()));
    }
    if let Some(value) = value.as_i64() {
        if (-MAX_SAFE_JSON_INTEGER..=MAX_SAFE_JSON_INTEGER).contains(&value) {
            return Ok(RequestId::Number(value));
        }
    }
    Err(GuardError::InvalidRequest(
        "MCP request id must be a string or JavaScript-safe integer".into(),
    ))
}

fn parse_progress_token(value: &Value) -> Result<ProgressToken> {
    match parse_request_id(value)? {
        RequestId::String(value) => Ok(ProgressToken::String(value)),
        RequestId::Number(value) => Ok(ProgressToken::Number(value)),
    }
}

fn finite_number(value: Option<&Value>, label: &str) -> Result<f64> {
    value
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite())
        .ok_or_else(|| GuardError::InvalidRequest(format!("{label} must be a finite number")))
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(GuardError::InvalidRequest(format!(
            "MCP object contains unknown field {field:?}"
        )));
    }
    Ok(())
}

fn validate_structure(value: &Value) -> Result<()> {
    let mut stack = vec![(value, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(GuardError::InvalidRequest(
                "MCP JSON exceeds the nesting or node limit".into(),
            ));
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(GuardError::InvalidRequest(
                    "MCP JSON contains an oversized string".into(),
                ));
            }
            Value::Array(values) => {
                if values.len() > MAX_JSON_CONTAINER_ENTRIES {
                    return Err(GuardError::InvalidRequest(
                        "MCP JSON array exceeds the entry limit".into(),
                    ));
                }
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > MAX_JSON_CONTAINER_ENTRIES {
                    return Err(GuardError::InvalidRequest(
                        "MCP JSON object exceeds the entry limit".into(),
                    ));
                }
                if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
                    return Err(GuardError::InvalidRequest(
                        "MCP JSON contains an oversized object key".into(),
                    ));
                }
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}
