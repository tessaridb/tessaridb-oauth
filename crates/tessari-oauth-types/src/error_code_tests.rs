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
        (ErrorCode::UnauthorizedClient, "unauthorized_client"),
        (ErrorCode::UnsupportedGrantType, "unsupported_grant_type"),
        (ErrorCode::InvalidDpopProof, "invalid_dpop_proof"),
    ] {
        assert_eq!(code.as_str(), wire);
    }
}
