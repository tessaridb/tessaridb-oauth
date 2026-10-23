use super::Change;

const ALL: [Change; 9] = [
    Change::PasswordChanged,
    Change::PasswordReset,
    Change::PasskeyAdded,
    Change::PasskeyRemoved,
    Change::AppEnrolled,
    Change::AppRemoved,
    Change::RecoveryCodesIssued,
    Change::RecoveryCodeUsed,
    Change::SignedOutEverywhere,
];

#[test]
fn each_change_keeps_the_reason_it_was_recorded_under() {
    let reasons: Vec<&str> = ALL.iter().map(|change| change.reason()).collect();
    assert_eq!(
        reasons,
        [
            "password_changed",
            "password_reset",
            "passkey_added",
            "passkey_removed",
            "totp_enrolled",
            "totp_removed",
            "recovery_codes_issued",
            "recovery_code_used",
            "signed_out_everywhere",
        ]
    );
}

#[test]
fn a_notice_names_its_change_and_its_issuer_and_carries_no_link_of_its_own() {
    let issuer = "https://id.example.com/acme";
    let mut said = Vec::new();
    for change in ALL {
        let (subject, text) = change.notice(issuer);
        assert_eq!(subject, "Your sign-in changed");
        assert!(text.contains(issuer), "{text}");
        assert!(text.contains(change.what()), "{text}");
        assert_eq!(
            text.matches("https://").count(),
            1,
            "only the issuer: {text}"
        );
        said.push(change.what());
    }
    said.sort_unstable();
    said.dedup();
    assert_eq!(
        said.len(),
        ALL.len(),
        "each change says something of its own"
    );
}
