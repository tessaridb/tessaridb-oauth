use super::authenticator::{
    AT, BE, CHALLENGE, ORIGIN, RP_ID, Signer, UP, UV, assertion_signature, attestation_object,
    authenticator_data, client_data,
};
use super::{Asserted, Expected, Registered, WebauthnRefused, assert, register};

pub(super) const CREDENTIAL_ID: &[u8] = b"credential-0001";

pub(super) fn expected(user_verification: bool) -> Expected<'static> {
    Expected {
        rp_id: RP_ID,
        origins: &[ORIGIN],
        challenge: CHALLENGE,
        user_verification,
    }
}

pub(super) fn registration(signer: &Signer, flags: u8) -> (Vec<u8>, Vec<u8>) {
    let key = signer.cose_key();
    let data = authenticator_data(RP_ID, flags, 0, Some((CREDENTIAL_ID, &key)));
    (
        client_data("webauthn.create", CHALLENGE, ORIGIN),
        attestation_object(&data),
    )
}

#[test]
fn a_registration_yields_the_credential_for_each_accepted_algorithm() {
    for signer in [Signer::ed25519(), Signer::p256(), Signer::rs256()] {
        let (client, attestation) = registration(&signer, UP | UV | BE | AT);
        assert_eq!(
            register(&client, &attestation, &expected(true)),
            Ok(Registered {
                credential_id: CREDENTIAL_ID.to_vec(),
                public_key: signer.cose_key(),
                sign_count: 0,
                user_verified: true,
                backup_eligible: true,
            })
        );
    }
}

#[test]
fn a_registration_is_refused_for_each_field_that_is_wrong() {
    let signer = Signer::p256();
    let key = signer.cose_key();
    let good_data = authenticator_data(RP_ID, UP | UV | AT, 0, Some((CREDENTIAL_ID, &key)));
    let good_client = client_data("webauthn.create", CHALLENGE, ORIGIN);
    let cases: [(&str, Vec<u8>, Vec<u8>, WebauthnRefused); 9] = [
        (
            "assertion client data",
            client_data("webauthn.get", CHALLENGE, ORIGIN),
            attestation_object(&good_data),
            WebauthnRefused::WrongCeremony,
        ),
        (
            "another challenge",
            client_data("webauthn.create", b"another challenge", ORIGIN),
            attestation_object(&good_data),
            WebauthnRefused::ChallengeMismatch,
        ),
        (
            "another origin",
            client_data("webauthn.create", CHALLENGE, "https://id.example.com.evil"),
            attestation_object(&good_data),
            WebauthnRefused::OriginNotAllowed,
        ),
        (
            "not JSON",
            b"{not json".to_vec(),
            attestation_object(&good_data),
            WebauthnRefused::ClientDataUnreadable,
        ),
        (
            "another relying party",
            good_client.clone(),
            attestation_object(&authenticator_data(
                "example.com",
                UP | UV | AT,
                0,
                Some((CREDENTIAL_ID, &key)),
            )),
            WebauthnRefused::RpIdMismatch,
        ),
        (
            "user not present",
            good_client.clone(),
            attestation_object(&authenticator_data(
                RP_ID,
                UV | AT,
                0,
                Some((CREDENTIAL_ID, &key)),
            )),
            WebauthnRefused::UserNotPresent,
        ),
        (
            "user not verified",
            good_client.clone(),
            attestation_object(&authenticator_data(
                RP_ID,
                UP | AT,
                0,
                Some((CREDENTIAL_ID, &key)),
            )),
            WebauthnRefused::UserNotVerified,
        ),
        (
            "no credential",
            good_client.clone(),
            attestation_object(&authenticator_data(RP_ID, UP | UV, 0, None)),
            WebauthnRefused::AttestationUnreadable,
        ),
        (
            "a key nobody accepts",
            good_client.clone(),
            attestation_object(&authenticator_data(
                RP_ID,
                UP | UV | AT,
                0,
                Some((CREDENTIAL_ID, b"\xa1\x01\x04")),
            )),
            WebauthnRefused::KeyNotAccepted,
        ),
    ];
    for (case, client, attestation, refusal) in cases {
        assert_eq!(
            register(&client, &attestation, &expected(true)),
            Err(refusal),
            "{case}"
        );
    }
    assert_eq!(
        register(&good_client, b"\xff\x00", &expected(true)),
        Err(WebauthnRefused::AttestationUnreadable),
        "not CBOR"
    );
    assert_eq!(
        register(&good_client, &vec![0_u8; 70_000], &expected(true)),
        Err(WebauthnRefused::TooLarge)
    );
}

fn assertion(signer: &Signer, flags: u8, count: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let client = client_data("webauthn.get", CHALLENGE, ORIGIN);
    let data = authenticator_data(RP_ID, flags, count, None);
    let signature = assertion_signature(signer, &data, &client);
    (client, data, signature)
}

#[test]
fn an_assertion_by_the_registered_key_verifies_for_each_accepted_algorithm() {
    for signer in [Signer::ed25519(), Signer::p256(), Signer::rs256()] {
        let (client, data, signature) = assertion(&signer, UP | UV, 8);
        assert_eq!(
            assert(
                &client,
                &data,
                &signature,
                &signer.cose_key(),
                7,
                &expected(true)
            ),
            Ok(Asserted {
                sign_count: 8,
                user_verified: true,
                clone_suspected: false,
            })
        );
    }
}

#[test]
fn an_assertion_is_refused_for_a_signature_by_another_key_or_over_other_data() {
    let signer = Signer::p256();
    let (client, data, signature) = assertion(&signer, UP | UV, 1);
    let other = Signer::p256();
    assert_eq!(
        assert(
            &client,
            &data,
            &signature,
            &other.cose_key(),
            0,
            &expected(true)
        ),
        Err(WebauthnRefused::SignatureInvalid),
        "another key"
    );
    let mut tampered = data.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    assert_eq!(
        assert(
            &client,
            &tampered,
            &signature,
            &signer.cose_key(),
            0,
            &expected(true)
        ),
        Err(WebauthnRefused::SignatureInvalid),
        "the counter changed after signing"
    );
    let other_client = client_data("webauthn.get", CHALLENGE, ORIGIN)
        .into_iter()
        .chain(*b" ")
        .collect::<Vec<u8>>();
    assert_eq!(
        assert(
            &other_client,
            &data,
            &signature,
            &signer.cose_key(),
            0,
            &expected(true)
        ),
        Err(WebauthnRefused::SignatureInvalid),
        "other client data"
    );
    assert_eq!(
        assert(
            &client_data("webauthn.create", CHALLENGE, ORIGIN),
            &data,
            &signature,
            &signer.cose_key(),
            0,
            &expected(true)
        ),
        Err(WebauthnRefused::WrongCeremony)
    );
    let (client, data, signature) = assertion(&signer, UP, 1);
    assert_eq!(
        assert(
            &client,
            &data,
            &signature,
            &signer.cose_key(),
            0,
            &expected(true)
        ),
        Err(WebauthnRefused::UserNotVerified),
        "verification required"
    );
    assert!(
        assert(
            &client,
            &data,
            &signature,
            &signer.cose_key(),
            0,
            &expected(false)
        )
        .is_ok(),
        "presence suffices when verification is not required"
    );
}

#[test]
fn a_counter_that_does_not_move_forward_is_reported_and_zero_is_not() {
    let signer = Signer::ed25519();
    let check = |count: u32, stored: u32| {
        let (client, data, signature) = assertion(&signer, UP | UV, count);
        assert(
            &client,
            &data,
            &signature,
            &signer.cose_key(),
            stored,
            &expected(true),
        )
        .map(|asserted| asserted.clone_suspected)
    };
    assert_eq!(check(5, 4), Ok(false));
    assert_eq!(check(5, 5), Ok(true), "the same counter again");
    assert_eq!(check(3, 5), Ok(true), "a counter behind");
    assert_eq!(check(0, 5), Ok(true), "a counter back at zero");
    assert_eq!(
        check(0, 0),
        Ok(false),
        "a synced passkey reports no counter"
    );
}

#[test]
fn an_assertion_carrying_a_credential_is_refused() {
    let signer = Signer::ed25519();
    let key = signer.cose_key();
    let client = client_data("webauthn.get", CHALLENGE, ORIGIN);
    let data = authenticator_data(RP_ID, UP | UV | AT, 1, Some((CREDENTIAL_ID, &key)));
    let signature = assertion_signature(&signer, &data, &client);
    assert_eq!(
        assert(&client, &data, &signature, &key, 0, &expected(true)),
        Err(WebauthnRefused::AuthenticatorDataUnreadable)
    );
}
