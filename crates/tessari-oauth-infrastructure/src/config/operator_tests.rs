use super::operator_target as target;

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn without_a_company_the_operator_is_made_in_system() {
    let (company, email) = target(&arguments(&["--email", "root@example.com"])).expect("read");
    assert_eq!(company.as_str(), "system");
    assert_eq!(email.as_str(), "root@example.com");
}

#[test]
fn a_company_is_named_before_or_after_the_address() {
    for words in [
        ["--company", "acme", "--email", "ops@acme.example"],
        ["--email", "ops@acme.example", "--company", "acme"],
    ] {
        let (company, email) = target(&arguments(&words)).expect("read");
        assert_eq!(
            (company.as_str(), email.as_str()),
            ("acme", "ops@acme.example")
        );
    }
}

#[test]
fn anything_else_is_refused_with_the_usage_or_the_bad_value() {
    for (words, says) in [
        (vec!["--email"], "--email <address>"),
        (vec!["--company", "acme"], "--email <address>"),
        (
            vec!["--company", "acme", "--company", "globex"],
            "--email <address>",
        ),
        (
            vec!["--company", "Acme", "--email", "ops@acme.example"],
            "a company id",
        ),
        (
            vec!["--company", "acme", "--email", "nobody"],
            "an email address",
        ),
    ] {
        let refused = target(&arguments(&words)).expect_err("refused").to_string();
        assert!(refused.contains(says), "{words:?}: {refused}");
    }
}
