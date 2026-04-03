use fast_core::{FastCipher, FastKey, Domain, SecurityLevel};
use proptest::prelude::*;

fn cipher() -> FastCipher {
    let key = FastKey::new(&[0u8; 16]).unwrap();
    FastCipher::new(&key, Domain::Decimal, SecurityLevel::Classical128).unwrap()
}

proptest! {
    #[test]
    fn prop_roundtrip_decimal(
        pt in "[0-9]{3,12}"
    ) {
        let c = cipher();
        let ct = c.encrypt(b"tweak", &pt).unwrap();
        prop_assert_eq!(ct.len(), pt.len());
        prop_assert!(ct.chars().all(|c| c.is_ascii_digit()));
        let recovered = c.decrypt(b"tweak", &ct).unwrap();
        prop_assert_eq!(recovered, pt);
    }

    #[test]
    fn prop_deterministic(
        pt in "[0-9]{5,10}",
        tweak in proptest::collection::vec(any::<u8>(), 0..20)
    ) {
        let c = cipher();
        let ct1 = c.encrypt(&tweak, &pt).unwrap();
        let ct2 = c.encrypt(&tweak, &pt).unwrap();
        prop_assert_eq!(ct1, ct2);
    }

    #[test]
    fn prop_different_tweaks_usually_different(
        pt in "[0-9]{6,10}",
    ) {
        let c = cipher();
        let ct1 = c.encrypt(b"tweak_a", &pt).unwrap();
        let ct2 = c.encrypt(b"tweak_b", &pt).unwrap();
        // Not guaranteed for very short inputs, but highly likely for 6+ digits
        prop_assert_ne!(ct1, ct2);
    }
}
