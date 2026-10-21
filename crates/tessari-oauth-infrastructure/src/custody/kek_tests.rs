use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use tessari_oauth_types::TenantId;

use super::Kek;
use crate::Error;

static FILES: AtomicU32 = AtomicU32::new(0);

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant")
}

/// A key file of `bytes` with `mode`, in a path nobody else uses.
fn file(bytes: &[u8], mode: u32) -> PathBuf {
    let turn = FILES.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("kek-test-{}-{turn}", std::process::id()));
    std::fs::write(&path, bytes).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode set");
    path
}

fn kek(byte: u8) -> Kek {
    Kek::load(&file(&[byte; 32], 0o600)).expect("a key file")
}

#[test]
fn a_sealed_secret_opens_only_for_the_same_tenant_kid_and_key() {
    let secret = b"pkcs8 private key bytes";
    let sealed = kek(1).seal(&tenant("acme"), "k1", secret).expect("sealed");
    assert!(
        !sealed.windows(secret.len()).any(|window| window == secret),
        "no plaintext in the sealed form"
    );
    assert_eq!(
        kek(1)
            .unseal(&tenant("acme"), "k1", &sealed)
            .expect("opened")
            .as_slice(),
        secret
    );
    for (key, tenant_name, kid) in [(1, "globex", "k1"), (1, "acme", "k2"), (2, "acme", "k1")] {
        assert!(
            kek(key).unseal(&tenant(tenant_name), kid, &sealed).is_err(),
            "{key} {tenant_name} {kid}"
        );
    }
    let mut flipped = sealed.clone();
    if let Some(byte) = flipped.last_mut() {
        *byte ^= 1;
    }
    assert!(kek(1).unseal(&tenant("acme"), "k1", &flipped).is_err());
    assert!(kek(1).unseal(&tenant("acme"), "k1", &sealed[..8]).is_err());
}

#[test]
fn two_seals_of_one_secret_differ() {
    let key = kek(1);
    assert_ne!(
        key.seal(&tenant("acme"), "k1", b"same").expect("sealed"),
        key.seal(&tenant("acme"), "k1", b"same").expect("sealed")
    );
}

#[test]
fn a_key_file_others_can_read_or_of_the_wrong_length_is_refused() {
    for path in [
        file(&[1; 32], 0o640),
        file(&[1; 32], 0o604),
        file(&[1; 31], 0o600),
        file(&[1; 33], 0o600),
    ] {
        assert!(
            matches!(
                Kek::load(&path),
                Err(Error::InvalidConfig {
                    field: "key_encryption_key",
                    ..
                })
            ),
            "{path:?}"
        );
    }
    assert!(Kek::load(&file(&[1; 32], 0o400)).is_ok());
}
