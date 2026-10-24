use std::path::Path;

use super::old_kek_path;

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn the_old_key_is_the_file_after_its_flag() {
    let path = old_kek_path(&arguments(&["--old-kek", "/keys/old.key"])).expect("read");
    assert_eq!(path, Path::new("/keys/old.key"));
}

#[test]
fn anything_else_is_refused_with_the_usage() {
    for words in [
        &[][..],
        &["--old-kek"][..],
        &["/keys/old.key"][..],
        &["--new-kek", "/keys/new.key"][..],
        &["--old-kek", "/keys/old.key", "--old-kek", "/keys/other.key"][..],
    ] {
        let refused = old_kek_path(&arguments(words)).expect_err("refused");
        assert!(
            refused.to_string().contains("--old-kek <file>"),
            "{words:?} answered {refused}"
        );
    }
}
