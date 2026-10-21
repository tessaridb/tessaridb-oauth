use super::ErrorCode;

#[test]
fn each_code_is_spelled_as_the_specification_spells_it() {
    for (code, wire) in [
        (ErrorCode::InvalidRequest, "invalid_request"),
        (
            ErrorCode::UnsupportedResponseType,
            "unsupported_response_type",
        ),
        (ErrorCode::InvalidScope, "invalid_scope"),
        (ErrorCode::InvalidClient, "invalid_client"),
        (ErrorCode::InvalidGrant, "invalid_grant"),
        (ErrorCode::UnsupportedGrantType, "unsupported_grant_type"),
    ] {
        assert_eq!(code.as_str(), wire);
    }
}
