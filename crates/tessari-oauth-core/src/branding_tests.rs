use super::{Accent, BrandLink, BrandName, BrandRefusal, contrast_with_white};

#[test]
fn a_name_is_trimmed_and_holds_no_control_or_direction_characters() {
    assert_eq!(
        BrandName::parse("  Acme Bank ").map(|name| name.as_str().to_owned()),
        Ok("Acme Bank".to_owned())
    );
    for refused in [
        "",
        "   ",
        "a\u{0007}b",
        "pay\u{202e}lap",
        "line\nbreak",
        &"x".repeat(65),
    ] {
        assert_eq!(
            BrandName::parse(refused),
            Err(BrandRefusal::NameInvalid),
            "{refused:?}"
        );
    }
    assert!(
        BrandName::parse("x".repeat(64)).is_ok(),
        "64 characters is the ceiling, not past it"
    );
    assert!(BrandName::parse("Ünïcödé Ltd").is_ok());
}

#[test]
fn an_accent_is_six_hex_digits_that_white_text_reads_on() {
    assert_eq!(
        Accent::parse("#1F4FD8").map(|accent| accent.as_str().to_owned()),
        Ok("#1f4fd8".to_owned())
    );
    for refused in [
        "1f4fd8",
        "#1f4fd",
        "#1f4fd8a",
        "#gggggg",
        "red",
        "#1f4fd8;}body{x",
        "",
        "#1F4F D8",
    ] {
        assert_eq!(
            Accent::parse(refused),
            Err(BrandRefusal::AccentInvalid),
            "{refused:?}"
        );
    }
    // Yellow on white text cannot be read.
    assert_eq!(
        Accent::parse("#ffd400"),
        Err(BrandRefusal::AccentLowContrast)
    );
    assert_eq!(
        Accent::parse("#ffffff"),
        Err(BrandRefusal::AccentLowContrast)
    );
    assert!(Accent::parse("#000000").is_ok());
}

#[test]
fn contrast_follows_the_wcag_luminance() {
    assert!((contrast_with_white(0, 0, 0) - 21.0).abs() < 0.01);
    assert!((contrast_with_white(255, 255, 255) - 1.0).abs() < 0.01);
    // #767676 is the lightest grey that passes 4.5:1 on white.
    assert!(contrast_with_white(0x76, 0x76, 0x76) >= 4.5);
    assert!(contrast_with_white(0x77, 0x77, 0x77) < 4.5);
}

#[test]
fn a_link_is_https_with_a_host_and_no_credentials() {
    assert_eq!(
        BrandLink::parse("https://help.acme.example/support").map(|link| link.as_str().to_owned()),
        Ok("https://help.acme.example/support".to_owned())
    );
    for refused in [
        "http://help.acme.example/",
        "javascript:alert(1)",
        "data:text/html,<b>x</b>",
        "https://user:pass@acme.example/",
        "https://",
        "//acme.example/",
        "",
        &format!("https://acme.example/{}", "a".repeat(2048)),
    ] {
        assert_eq!(
            BrandLink::parse(refused),
            Err(BrandRefusal::LinkInvalid),
            "{refused:?}"
        );
    }
}

#[test]
fn every_refusal_has_one_stable_code() {
    let codes = [
        BrandRefusal::NameInvalid,
        BrandRefusal::AccentInvalid,
        BrandRefusal::AccentLowContrast,
        BrandRefusal::LinkInvalid,
        BrandRefusal::LogoTooLarge,
        BrandRefusal::LogoNotPng,
        BrandRefusal::LogoUnreadable,
        BrandRefusal::LogoTooWide,
    ]
    .map(BrandRefusal::code);
    assert_eq!(
        codes,
        [
            "brand_name_invalid",
            "accent_invalid",
            "accent_low_contrast",
            "link_invalid",
            "logo_too_large",
            "logo_not_png",
            "logo_unreadable",
            "logo_too_wide",
        ]
    );
}
