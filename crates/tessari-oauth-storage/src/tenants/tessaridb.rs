//! Tenant provisioning on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place};

use super::repository::TenantRepository;
use crate::Result;

/// The tables of a tenant's database. Every definition carries `IF NOT EXISTS`, so provisioning is re-runnable.
///
/// `codes` holds the bindings of each issued authorization code, its resources among them, under the code's digest;
/// `redeemed_at` is absent until the single redemption sets it. `consents` holds one grant per user and client; it
/// is indexed by user because a user's grant list is read by user, while every check reads one record by its id.
/// `refresh_families` and `refresh_tokens` hold each family and each of its tokens under a digest; a token is read by
/// id, and the families an account event revokes are found by user or by client. `signing_keys` holds each key sealed with its public half and dates; it is listed whole, oldest first.
/// `replays` is a space of spent client assertions and DPoP proofs whose keys expire with what they record.
/// `interactions` holds each pending authorization — a validated `/authorize` request waiting for its user to sign
/// in, or a pushed one (RFC 9126) waiting unclaimed for its browser — under a random id, and the store expires it
/// after ten minutes (`INTERACTION_TTL_SECS`); every read and the single claim are by id.
/// `audit` is a topic of one message per issuance, refusal, replay, reuse and revocation, which the store keeps in commit
/// order and never lets anyone rewrite or delete; a message is kept for 400 days.
/// `clients` holds each client's registration under its id; every read is by id. `secrets` holds the tenant's sealed
/// secrets under the id naming their purpose — the pairwise salt.
/// `users` holds each account under its random id; `user_emails` holds the address an account signs in with under the
/// address itself, so an address belongs to one account and sign-in finds it by id; `credentials` holds an account's
/// password hash under the account's id. `totp_factors` holds a user's one-time code secret, sealed, with the last step a
/// code was accepted for, and `totp_pending` the secret a session is enrolling, sealed, under the session's public id
/// for the ten minutes enrolment may take; `recovery_codes` holds each recovery code under its owner and digest,
/// indexed by user so a new set replaces the old. `passkeys` holds each credential under its credential id, so an id
/// has one owner; `passkey_challenges` holds each issued challenge under the challenge itself for the five minutes
/// (`WEBAUTHN_CHALLENGE_TTL_SECS`) it may be answered in. `signins` holds one browser's sign-in in progress under the
/// digest of its sign-in cookie value, for the ten minutes (`INTERACTION_TTL_SECS`) its authorization request is kept.
/// `sessions` holds a user's session under the digest of its session cookie value, for at most the week
/// (`SESSION_ABSOLUTE_SECS`) a session lasts, found for its user's own list by `by_user`.
/// `enrolments` holds a user's one live enrolment code under its digest for 72 hours, found by `by_user` when a new code
/// replaces it. `operator_grants` holds each role a user may administer the company with under `<user id>.<role>`,
/// with who gave it, why and until when, found for its holder by `by_user`. `admin_signins` holds a sign-in to the
/// admin console under the digest of its sign-in cookie for the ten minutes (`ADMIN_SIGNIN_TTL_SECS`) a trip to the
/// issuer may take; `admin_sessions` holds an admin console session under the digest of its cookie for at most the
/// eight hours (`ADMIN_SESSION_ABSOLUTE_SECS`) it lasts; `admin_actions` holds an operator's change under its operator
/// and idempotency key for the day a repeat of it is answered from. `groups` holds each group under its id with the
/// roles it carries; `group_members` holds each membership under `<group id>.<user id>`, found for a group's member
/// list by `by_group` and for a user's claims by `by_user`.
const TABLES: &str = "DEFINE TABLE IF NOT EXISTS codes (\
     tenant string REQUIRED, client_id string REQUIRED, user_id string REQUIRED, redirect_uri string REQUIRED, \
     challenge string REQUIRED, scopes array REQUIRED, resources array REQUIRED, expires_at int REQUIRED, \
     auth_time int REQUIRED, methods array REQUIRED, sid string REQUIRED, nonce string, redeemed_at int); \
     DEFINE TABLE IF NOT EXISTS consents (\
     tenant string REQUIRED, user_id string REQUIRED, client_id string REQUIRED, scopes array REQUIRED, \
     resources array REQUIRED, policy_version int REQUIRED, shown_version string REQUIRED, \
     granted_at int REQUIRED, revision int REQUIRED, revoked_at int, revoked_by string); \
     DEFINE INDEX IF NOT EXISTS by_user ON consents FIELDS user_id; \
     DEFINE INDEX IF NOT EXISTS by_client ON consents FIELDS client_id; \
     DEFINE TABLE IF NOT EXISTS refresh_families (\
     tenant string REQUIRED, client_id string REQUIRED, user_id string REQUIRED, created_at int REQUIRED, \
     expires_at int REQUIRED, revoked_at int, revoked_reason string); \
     DEFINE INDEX IF NOT EXISTS by_user ON refresh_families FIELDS user_id; \
     DEFINE INDEX IF NOT EXISTS by_client ON refresh_families FIELDS client_id; \
     DEFINE TABLE IF NOT EXISTS refresh_tokens (\
     family_id string REQUIRED, tenant string REQUIRED, client_id string REQUIRED, user_id string REQUIRED, \
     scopes array REQUIRED, resources array REQUIRED, idle_expires_at int REQUIRED, rotated_at int, jkt string); \
     DEFINE TABLE IF NOT EXISTS signing_keys (\
     kid string REQUIRED, tenant string REQUIRED, algorithm string REQUIRED, sealed string REQUIRED, \
     public_jwk string REQUIRED, created_at int REQUIRED, compromised bool REQUIRED, retired_at int); \
     DEFINE TABLE IF NOT EXISTS interactions (\
     tenant string REQUIRED, client_id string REQUIRED, redirect_uri string REQUIRED, scopes array REQUIRED, \
     challenge string REQUIRED, state string, resources array REQUIRED, nonce string, silent bool REQUIRED, \
     max_age int, created_at int REQUIRED, claimed_at int, browser string) \
     EXPIRE AFTER 10m; \
     DEFINE SPACE IF NOT EXISTS replays; \
     DEFINE TOPIC IF NOT EXISTS audit RETAIN 400d; \
     DEFINE TABLE IF NOT EXISTS clients (\
     client_id string REQUIRED, tenant string REQUIRED, redirect_uris array REQUIRED, scope_ceiling array REQUIRED, \
     resources array REQUIRED, auth_method string REQUIRED, \
     assertion_alg string, grant_types array REQUIRED, jwks array REQUIRED, dpop_bound_access_tokens bool REQUIRED, \
     registered_at int REQUIRED); \
     DEFINE FIELD IF NOT EXISTS post_logout_redirect_uris ON clients TYPE array; \
     DEFINE FIELD IF NOT EXISTS backchannel_logout_uri ON clients TYPE string; \
     DEFINE TABLE IF NOT EXISTS secrets (sealed string REQUIRED, created_at int REQUIRED); \
     DEFINE TABLE IF NOT EXISTS users (\
     user_id string REQUIRED, tenant string REQUIRED, status string REQUIRED, created_at int REQUIRED); \
     DEFINE TABLE IF NOT EXISTS user_emails (\
     address string REQUIRED, user_id string REQUIRED, verified_at int, verified_by string); \
     DEFINE INDEX IF NOT EXISTS by_user ON user_emails FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS credentials (\
     user_id string REQUIRED, hash string REQUIRED, pepper int REQUIRED, updated_at int REQUIRED); \
     DEFINE TABLE IF NOT EXISTS totp_factors (\
     user_id string REQUIRED, sealed string REQUIRED, last_step int REQUIRED, created_at int REQUIRED); \
     DEFINE TABLE IF NOT EXISTS totp_pending (\
     user_id string REQUIRED, sealed string REQUIRED, created_at int REQUIRED) EXPIRE AFTER 10m; \
     DEFINE TABLE IF NOT EXISTS recovery_codes (user_id string REQUIRED, created_at int REQUIRED); \
     DEFINE INDEX IF NOT EXISTS by_user ON recovery_codes FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS passkeys (\
     user_id string REQUIRED, public_key string REQUIRED, sign_count int REQUIRED, backup_eligible bool REQUIRED, \
     created_at int REQUIRED); \
     DEFINE INDEX IF NOT EXISTS by_user ON passkeys FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS passkey_challenges (\
     ceremony string REQUIRED, user_id string, created_at int REQUIRED) \
     EXPIRE AFTER 5m; \
     DEFINE TABLE IF NOT EXISTS two_factor (\
     policy string REQUIRED ASSERT $value IN ['off', 'optional', 'required']); \
     DEFINE TABLE IF NOT EXISTS signins (\
     interaction string, identified bool REQUIRED, user_id string, second_factor bool REQUIRED, \
     account string, methods array REQUIRED, revision int REQUIRED, created_at int REQUIRED) \
     EXPIRE AFTER 10m; \
     DEFINE TABLE IF NOT EXISTS sessions (\
     user_id string REQUIRED, sid string REQUIRED, methods array REQUIRED, auth_time int REQUIRED, \
     seen_at int REQUIRED) EXPIRE AFTER 7d; \
     DEFINE FIELD IF NOT EXISTS clients ON sessions TYPE array; \
     DEFINE QUEUE IF NOT EXISTS logout_deliveries TIMEOUT 30s ATTEMPTS 10 SCHEMAFULL NOT BEFORE due; \
     DEFINE FIELD IF NOT EXISTS user_id ON logout_deliveries TYPE string REQUIRED; \
     DEFINE FIELD IF NOT EXISTS sid ON logout_deliveries TYPE string REQUIRED; \
     DEFINE FIELD IF NOT EXISTS clients ON logout_deliveries TYPE array REQUIRED; \
     DEFINE FIELD IF NOT EXISTS due ON logout_deliveries TYPE datetime REQUIRED; \
     DEFINE EVENT OR REPLACE tell_clients ON sessions FOR DELETE WHEN array::len($before.clients ?? []) > 0 \
     THEN CREATE logout_deliveries:$id = { user_id: $before.user_id, sid: $before.sid, clients: $before.clients, \
     due: time::now() }; \
     DEFINE INDEX IF NOT EXISTS by_user ON sessions FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS enrolments (\
     user_id string REQUIRED, created_at int REQUIRED, created_by string REQUIRED) EXPIRE AFTER 72h; \
     DEFINE INDEX IF NOT EXISTS by_user ON enrolments FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS operator_grants (\
     user_id string REQUIRED, role_name string REQUIRED, granted_by string REQUIRED, granted_at int REQUIRED, \
     reason string REQUIRED); \
     DEFINE FIELD IF NOT EXISTS expires_at ON operator_grants TYPE int; \
     DEFINE INDEX IF NOT EXISTS by_user ON operator_grants FIELDS user_id; \
     DEFINE TABLE IF NOT EXISTS admin_signins (\
     state string REQUIRED, verifier string REQUIRED, nonce string REQUIRED, created_at int REQUIRED) \
     EXPIRE AFTER 10m; \
     DEFINE TABLE IF NOT EXISTS admin_sessions (\
     user_id string REQUIRED, sid string REQUIRED, methods array REQUIRED, auth_time int REQUIRED, \
     seen_at int REQUIRED) EXPIRE AFTER 8h; \
     DEFINE TABLE IF NOT EXISTS admin_actions (\
     operator string REQUIRED, action string REQUIRED, request string REQUIRED, created_at int REQUIRED) \
     EXPIRE AFTER 24h; \
     DEFINE FIELD IF NOT EXISTS status ON admin_actions TYPE int; \
     DEFINE FIELD IF NOT EXISTS answer ON admin_actions TYPE string; \
     DEFINE TABLE IF NOT EXISTS groups (\
     group_id string REQUIRED, tenant string REQUIRED, description string REQUIRED, roles array REQUIRED, \
     created_at int REQUIRED); \
     DEFINE TABLE IF NOT EXISTS group_members (\
     group_id string REQUIRED, user_id string REQUIRED, added_at int REQUIRED, added_by string REQUIRED); \
     DEFINE INDEX IF NOT EXISTS by_group ON group_members FIELDS group_id; \
     DEFINE INDEX IF NOT EXISTS by_user ON group_members FIELDS user_id;";

pub(crate) struct TessaridbTenantRepository {
    database: Database,
}

impl TessaridbTenantRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl TenantRepository for TessaridbTenantRepository {
    async fn provision(&self, place: &Place) -> Result<()> {
        // Names are checked plain by `Place`, which is what allows them into the text; nothing else is.
        // The containers are declared before the transaction: on 0.36.2 a `USE` of a namespace declared inside the
        // still-open transaction is refused as outside the user's reach. Each container declaration is re-runnable
        // on its own; the tables, which belong together, go in one transaction.
        let namespace = place.namespace();
        let database = place.database();
        let script = format!(
            "DEFINE NAMESPACE IF NOT EXISTS {namespace}; USE NAMESPACE {namespace}; \
             DEFINE DATABASE IF NOT EXISTS {database}; USE DATABASE {database}; BEGIN; {TABLES} COMMIT;"
        );
        self.database.run_unplaced(&script, Vec::new()).await?;
        Ok(())
    }
}
