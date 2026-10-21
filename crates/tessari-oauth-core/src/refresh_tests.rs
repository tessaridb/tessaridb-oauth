use tessari_oauth_types::{ErrorCode, RefreshToken, ScopeSet};

use super::{presented, scopes};
use crate::Reason;
use crate::token::{Refusal, read};

fn granted() -> ScopeSet {
    ScopeSet::parse("openid profile notes:read").expect("fixture")
}

fn request(extra: &[(&'static str, &str)]) -> crate::Params {
    let mut pairs = vec![
        ("grant_type", "refresh_token".to_owned()),
        ("client_id", "app".to_owned()),
    ];
    pairs.extend(
        extra
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    read(pairs).expect("no repeats")
}

#[test]
fn the_presented_token_is_required_and_read_as_a_refresh_token() {
    assert_eq!(
        presented(&request(&[("refresh_token", "rt-secret")])),
        Ok(RefreshToken::from_secret("rt-secret"))
    );
    assert_eq!(
        presented(&request(&[])),
        Err(Refusal {
            error: ErrorCode::InvalidRequest,
            reason: Reason::MissingParameter
        })
    );
}

#[test]
fn no_scope_keeps_the_grant_and_a_subset_narrows_it() {
    assert_eq!(scopes(&request(&[]), &granted()), Ok(granted()));
    assert_eq!(
        scopes(&request(&[("scope", "notes:read openid")]), &granted()),
        Ok(ScopeSet::parse("openid notes:read").expect("fixture"))
    );
}

#[test]
fn a_scope_beyond_the_grant_is_refused_rather_than_narrowed() {
    for asked in [
        "notes:write",
        "openid notes:write",
        "openid profile notes:read email",
    ] {
        assert_eq!(
            scopes(&request(&[("scope", asked)]), &granted()),
            Err(Refusal {
                error: ErrorCode::InvalidScope,
                reason: Reason::ScopeBeyondGrant
            }),
            "{asked}"
        );
    }
}

#[test]
fn a_malformed_scope_is_refused() {
    for asked in ["", "openid  profile", "bad\"scope"] {
        assert_eq!(
            scopes(&request(&[("scope", asked)]), &granted()),
            Err(Refusal {
                error: ErrorCode::InvalidScope,
                reason: Reason::MalformedParameter
            }),
            "{asked:?}"
        );
    }
}

#[test]
fn a_refresh_names_one_audience_among_the_familys_resources() {
    let resources = std::collections::BTreeSet::from([
        tessari_oauth_types::Resource::parse("https://api.example.com/").expect("fixture"),
        tessari_oauth_types::Resource::parse("https://files.example.com/").expect("fixture"),
    ]);
    let named = request(&[("resource", "https://files.example.com/")]);
    assert_eq!(
        crate::token::audience(&named, &resources).map(|resource| resource.as_str().to_owned()),
        Ok("https://files.example.com/".to_owned())
    );
    let unnamed = request(&[]);
    assert_eq!(
        crate::token::audience(&unnamed, &resources),
        Err(Refusal {
            error: ErrorCode::InvalidTarget,
            reason: Reason::TargetUnnamed,
        })
    );
}
