#![no_main]

use libfuzzer_sys::fuzz_target;
use scopepact_guard::mcp::{ConnectionTracker, Direction, classify_message};

fuzz_target!(|data: &[u8]| {
    let Ok(message) = serde_json::from_slice(data) else {
        return;
    };
    if let Ok(class) = classify_message(&message) {
        let mut tracker = ConnectionTracker::default();
        let _ = tracker.accept(Direction::ClientToServer, &message, &class);
        let _ = tracker.accept(Direction::ServerToClient, &message, &class);
    }
});
