#![no_main]

use libfuzzer_sys::fuzz_target;
use scopepact_guard::policy_bundle::{PolicyIssuerTrust, SignedPolicyBundle, verify_policy_bundle};
use scopepact_guard::{GuardPolicy, SignedDecisionReceipt, validate_policy};

fuzz_target!(|data: &[u8]| {
    if let Ok(policy) = serde_json::from_slice::<GuardPolicy>(data) {
        let _ = validate_policy(&policy);
    }
    if let Ok(receipt) = serde_json::from_slice::<SignedDecisionReceipt>(data) {
        let _ = receipt.verify();
    }
    if let Ok(signed) = serde_json::from_slice::<SignedPolicyBundle>(data) {
        let trust = PolicyIssuerTrust::pinned(
            signed.bundle.audience.clone(),
            signed.bundle.issuer.clone(),
            signed.signer_public_key.clone(),
            signed.signer_key_id.clone(),
            signed.bundle.issued_at_ms,
            Some(signed.bundle.expires_at_ms),
        );
        if let Ok(trust) = trust {
            let _ = verify_policy_bundle(
                &signed,
                &trust,
                &signed.bundle.audience,
                signed.bundle.not_before_ms,
            );
        }
    }
});
