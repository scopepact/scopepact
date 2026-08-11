use scopepact_guard::mcp::{
    ConnectionTracker, Direction, ForwardDisposition, MAX_JSON_CONTAINER_ENTRIES, MAX_JSON_DEPTH,
    MAX_JSON_NODES, MAX_JSON_STRING_BYTES, MAX_PENDING_REQUESTS, classify_message,
};
use serde_json::{Value, json};

fn initialize_request(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1"}
        }
    })
}

fn initialize_response(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "test-server", "version": "1"}
        }
    })
}

fn accept(tracker: &mut ConnectionTracker, direction: Direction, message: &Value) {
    let class = classify_message(message).unwrap();
    assert_eq!(
        tracker.accept(direction, message, &class).unwrap(),
        ForwardDisposition::Forward
    );
}

fn activate(tracker: &mut ConnectionTracker) {
    accept(
        tracker,
        Direction::ClientToServer,
        &initialize_request(&json!("init-1")),
    );
    accept(
        tracker,
        Direction::ServerToClient,
        &initialize_response(&json!("init-1")),
    );
    accept(
        tracker,
        Direction::ClientToServer,
        &json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    );
}

#[test]
fn enforces_initialization_and_exact_response_correlation() {
    let mut tracker = ConnectionTracker::default();
    let premature = json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"});
    let class = classify_message(&premature).unwrap();
    assert!(
        tracker
            .accept(Direction::ClientToServer, &premature, &class)
            .is_err()
    );

    activate(&mut tracker);
    let request = json!({"jsonrpc":"2.0", "id":"01", "method":"tools/list"});
    accept(&mut tracker, Direction::ClientToServer, &request);

    let wrong_type = json!({"jsonrpc":"2.0", "id":1, "result":{}});
    let class = classify_message(&wrong_type).unwrap();
    assert!(
        tracker
            .accept(Direction::ServerToClient, &wrong_type, &class)
            .is_err()
    );
    accept(
        &mut tracker,
        Direction::ServerToClient,
        &json!({"jsonrpc":"2.0", "id":"01", "result":{}}),
    );
}

#[test]
fn rejects_invalid_json_rpc_shapes_and_versions() {
    for invalid in [
        json!([]),
        json!({"jsonrpc":"1.0", "id":1, "method":"ping"}),
        json!({"jsonrpc":"2.0", "id":null, "method":"ping"}),
        json!({"jsonrpc":"2.0", "id":1, "result":{}, "error":{"code":-1,"message":"x"}}),
        json!({"jsonrpc":"2.0", "method":"ping", "params":[]}),
        json!({"jsonrpc":"2.0", "id":1, "method":"ping", "extra":true}),
    ] {
        assert!(classify_message(&invalid).is_err());
    }

    let mut tracker = ConnectionTracker::default();
    let mut wrong_version = initialize_request(&json!(1));
    wrong_version["params"]["protocolVersion"] = json!("2025-03-26");
    let class = classify_message(&wrong_version).unwrap();
    assert!(
        tracker
            .accept(Direction::ClientToServer, &wrong_version, &class)
            .is_err()
    );
}

#[test]
fn validates_progress_cancellation_and_server_request_policy() {
    let mut tracker = ConnectionTracker::default();
    activate(&mut tracker);
    let request = json!({
        "jsonrpc":"2.0",
        "id":7,
        "method":"tools/list",
        "params":{"_meta":{"progressToken":"progress-7"}}
    });
    accept(&mut tracker, Direction::ClientToServer, &request);
    accept(
        &mut tracker,
        Direction::ServerToClient,
        &json!({
            "jsonrpc":"2.0",
            "method":"notifications/progress",
            "params":{"progressToken":"progress-7", "progress":1}
        }),
    );
    let repeated = json!({
        "jsonrpc":"2.0",
        "method":"notifications/progress",
        "params":{"progressToken":"progress-7", "progress":1}
    });
    let class = classify_message(&repeated).unwrap();
    assert!(
        tracker
            .accept(Direction::ServerToClient, &repeated, &class)
            .is_err()
    );
    accept(
        &mut tracker,
        Direction::ClientToServer,
        &json!({
            "jsonrpc":"2.0",
            "method":"notifications/cancelled",
            "params":{"requestId":7, "reason":"test"}
        }),
    );

    let sampling = json!({"jsonrpc":"2.0", "id":"s1", "method":"sampling/createMessage"});
    let class = classify_message(&sampling).unwrap();
    assert_eq!(
        tracker
            .accept(Direction::ServerToClient, &sampling, &class)
            .unwrap(),
        ForwardDisposition::RejectServerRequest {
            id: json!("s1"),
            method: "sampling/createMessage".into()
        }
    );

    let ping = json!({"jsonrpc":"2.0", "id":"p1", "method":"ping"});
    accept(&mut tracker, Direction::ServerToClient, &ping);
    accept(
        &mut tracker,
        Direction::ClientToServer,
        &json!({"jsonrpc":"2.0", "id":"p1", "result":{}}),
    );
}

#[test]
fn rejects_excessive_json_nesting() {
    let mut value = json!(null);
    for _ in 0..=MAX_JSON_DEPTH {
        value = json!([value]);
    }
    assert!(classify_message(&value).is_err());
}

#[test]
fn rejects_excessive_strings_containers_and_node_counts() {
    let oversized_string = json!({
        "jsonrpc":"2.0",
        "method":"notifications/test",
        "params":{"value":"x".repeat(MAX_JSON_STRING_BYTES + 1)}
    });
    assert!(
        classify_message(&oversized_string)
            .unwrap_err()
            .to_string()
            .contains("oversized string")
    );

    let oversized_container = json!({
        "jsonrpc":"2.0",
        "method":"notifications/test",
        "params":{"values":vec![Value::Null; MAX_JSON_CONTAINER_ENTRIES + 1]}
    });
    assert!(
        classify_message(&oversized_container)
            .unwrap_err()
            .to_string()
            .contains("entry limit")
    );

    let width = MAX_JSON_CONTAINER_ENTRIES;
    let inner_width = MAX_JSON_NODES / width + 1;
    let many_nodes = json!({
        "jsonrpc":"2.0",
        "method":"notifications/test",
        "params":{"values":vec![vec![Value::Null; inner_width]; width]}
    });
    assert!(
        classify_message(&many_nodes)
            .unwrap_err()
            .to_string()
            .contains("node limit")
    );
}

#[test]
fn pending_request_limit_is_enforced_per_direction() {
    let mut tracker = ConnectionTracker::default();
    activate(&mut tracker);
    for id in 0..MAX_PENDING_REQUESTS {
        accept(
            &mut tracker,
            Direction::ClientToServer,
            &json!({"jsonrpc":"2.0", "id":id, "method":"tools/list"}),
        );
    }
    let overflow = json!({
        "jsonrpc":"2.0",
        "id":MAX_PENDING_REQUESTS,
        "method":"tools/list"
    });
    let class = classify_message(&overflow).unwrap();
    let error = tracker
        .accept(Direction::ClientToServer, &overflow, &class)
        .unwrap_err();
    assert!(error.to_string().contains("pending request limit"));
}
