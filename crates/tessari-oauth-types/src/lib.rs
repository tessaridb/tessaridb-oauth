//! Protocol values that cross crate boundaries, each a type rather than a string, so that a mix-up between
//! two of them is a compile error: PKCE challenges, key thumbprints, redirect URIs, tenant and client ids, and
//! the error taxonomy every crate maps its failures into.

mod algorithm;
mod authorization_code;
pub mod base64url;
mod browser_binding;
mod category;
mod client_id;
mod email;
mod error;
mod error_code;
mod pkce;
mod redirect_uri;
mod refresh_token;
mod resource;
mod scope;
mod session_secret;
mod signin_binding;
mod tenant_id;
mod thumbprint;
mod timestamp;
mod user_id;

pub use algorithm::Algorithm;
pub use authorization_code::AuthorizationCode;
pub use browser_binding::BrowserBinding;
pub use category::ErrorCategory;
pub use client_id::ClientId;
pub use email::EmailAddress;
pub use error::{Error, Result};
pub use error_code::ErrorCode;
pub use pkce::Challenge;
pub use redirect_uri::RedirectUri;
pub use refresh_token::RefreshToken;
pub use resource::Resource;
pub use scope::ScopeSet;
pub use session_secret::SessionSecret;
pub use signin_binding::SigninBinding;
pub use tenant_id::TenantId;
pub use thumbprint::KeyThumbprint;
pub use timestamp::{Clock, Timestamp};
pub use user_id::UserId;
