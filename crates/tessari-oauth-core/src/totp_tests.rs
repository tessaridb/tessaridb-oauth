use tessari_oauth_constants::TOTP_STEP_SECS;
use tessari_oauth_types::Timestamp;

use super::{TotpRefused, base32, code_at, provisioning, verify};

/// RFC 6238 Appendix B: the SHA-1 seed.
const SEED: &[u8] = b"12345678901234567890";

#[test]
fn codes_match_the_rfc_6238_sha1_vectors() {
    // Appendix B gives eight digits; six are the same value modulo 10^6 (RFC 4226 §5.3).
    for (time, eight) in [
        (59_u64, 94_287_082_u32),
        (1_111_111_109, 7_081_804),
        (1_111_111_111, 14_050_471),
        (1_234_567_890, 89_005_924),
        (2_000_000_000, 69_279_037),
        (20_000_000_000, 65_353_130),
    ] {
        assert_eq!(
            code_at(SEED, time / TOTP_STEP_SECS),
            eight % 1_000_000,
            "T = {time}"
        );
    }
}

fn presented(time: u64) -> String {
    format!("{:06}", code_at(SEED, time / TOTP_STEP_SECS))
}

const NOW: u64 = 1_111_111_111;

fn check(code: &str, last_step: Option<u64>) -> Result<u64, TotpRefused> {
    verify(SEED, code, Timestamp::from_unix_secs(NOW), last_step)
}

#[test]
fn a_code_of_this_step_or_one_either_side_is_accepted_once() {
    let step = NOW / TOTP_STEP_SECS;
    assert_eq!(check(&presented(NOW), None), Ok(step));
    assert_eq!(check(&presented(NOW - TOTP_STEP_SECS), None), Ok(step - 1));
    assert_eq!(check(&presented(NOW + TOTP_STEP_SECS), None), Ok(step + 1));
    for far in [NOW - 2 * TOTP_STEP_SECS, NOW + 2 * TOTP_STEP_SECS] {
        assert_eq!(
            check(&presented(far), None),
            Err(TotpRefused::Wrong),
            "{far}"
        );
    }
    assert_eq!(
        check(&presented(NOW), Some(step)),
        Err(TotpRefused::Replayed),
        "the same step again"
    );
    assert_eq!(
        check(&presented(NOW - TOTP_STEP_SECS), Some(step)),
        Err(TotpRefused::Replayed),
        "an earlier step after a later one"
    );
    assert_eq!(
        check(&presented(NOW + TOTP_STEP_SECS), Some(step)),
        Ok(step + 1),
        "a later step after an earlier one"
    );
}

#[test]
fn a_code_that_is_not_six_digits_is_malformed() {
    let good = presented(NOW);
    for code in [
        String::new(),
        good[..5].to_owned(),
        format!("{good}0"),
        format!(" {}", &good[1..]),
        "12a456".to_owned(),
        "\u{661}23456".to_owned(),
    ] {
        assert_eq!(check(&code, None), Err(TotpRefused::Malformed), "{code:?}");
    }
    let window = [NOW - TOTP_STEP_SECS, NOW, NOW + TOTP_STEP_SECS].map(presented);
    let wrong = (0..1_000_000_u32)
        .map(|value| format!("{value:06}"))
        .find(|code| !window.contains(code))
        .expect("a code outside the window");
    assert_eq!(
        check(&wrong, None),
        Err(TotpRefused::Wrong),
        "six digits, wrong"
    );
}

#[test]
fn a_secret_is_written_in_unpadded_rfc_4648_base32() {
    // RFC 4648 §10, the padding left off as authenticator apps read it.
    for (bytes, text) in [
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ] {
        assert_eq!(base32(bytes.as_bytes()), text, "{bytes:?}");
    }
}

#[test]
fn the_provisioning_uri_names_the_issuer_the_account_and_the_parameters_codes_are_checked_with() {
    let (secret, uri) = provisioning("Acme & Co", "ada@example.com", b"12345678901234567890");
    assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert_eq!(
        uri,
        "otpauth://totp/Acme%20%26%20Co:ada%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&\
         issuer=Acme%20%26%20Co&algorithm=SHA1&digits=6&period=30"
    );
}
