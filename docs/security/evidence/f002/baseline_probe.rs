//! Isolated pre-change reproduction; NOT a post-change regression.
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_gov::verify::{sign_envelope, verify_envelope_threshold};
use qbind_gov::{verify_envelope, CouncilKey, CouncilKeySet, UpgradeEnvelope};

#[test]
fn baseline_one_copied_approval_satisfies_two_of_three() {
    let mut envelope = UpgradeEnvelope::from_json(
        r#"{"envelope_version":"1.0","envelope_id":"F002-disposable",
        "protocol_version":"0.1.0","network_environment":"test",
        "class":"c_hard_fork","activation_height":1,
        "binary_hashes":{"linux-x86_64":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
    )
    .unwrap();
    envelope.validate().unwrap();
    let mut keys = Vec::new();
    let mut approvals = Vec::new();
    for id in ["a", "b", "c"] {
        let (pk, sk) = MlDsa44Backend::generate_keypair().unwrap();
        let pk = hex::encode(pk);
        approvals.push(sign_envelope(&envelope, id, &pk, &sk).unwrap());
        keys.push(CouncilKey::new(id, pk));
    }
    assert_ne!(keys[0].public_key, keys[1].public_key);
    assert_ne!(keys[0].public_key, keys[2].public_key);
    assert_ne!(keys[1].public_key, keys[2].public_key);
    let keyset = CouncilKeySet::new(2, keys);
    keyset.validate().unwrap();
    envelope.council_approvals = vec![approvals[0].clone()];
    envelope.validate().unwrap();
    let single = verify_envelope(&envelope, &keyset).unwrap();
    assert_eq!(single.valid_count, 1);
    assert!(!single.is_valid());
    assert!(matches!(
        verify_envelope_threshold(&envelope, &keyset),
        Err(qbind_gov::EnvelopeError::ThresholdNotMet { required: 2, actual: 1 })
    ));
    println!("single genuine approval: count=1 threshold=2 valid=false; wrapper rejects");
    envelope.council_approvals.push(approvals[1].clone());
    envelope.validate().unwrap();
    assert_eq!(verify_envelope(&envelope, &keyset).unwrap().valid_count, 2);
    assert!(verify_envelope_threshold(&envelope, &keyset).unwrap().is_valid());
    println!("two distinct genuine approvals: count=2 threshold=2 valid=true; wrapper accepts");
    envelope.council_approvals[1] = approvals[0].clone();
    envelope.validate().unwrap();
    let copied = verify_envelope(&envelope, &keyset).unwrap();
    assert_eq!(copied.valid_count, 2);
    assert!(copied.is_valid());
    assert!(verify_envelope_threshold(&envelope, &keyset).unwrap().is_valid());
    println!("one genuine approval copied twice: count=2 threshold=2 valid=true; wrapper accepts (baseline defect)");
}
