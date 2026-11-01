use age::secrecy::{ExposeSecret, SecretString};
use age_desktop::crypto::{self, Credential, Job, Operation, Progress};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};

fn execute(
    input: &Path,
    output: &Path,
    operation: Operation,
    armor: bool,
    credential: Credential,
) -> Vec<crypto::FileResult> {
    crypto::run(
        Job {
            inputs: vec![input.to_owned()],
            output_dir: Some(output.to_owned()),
            operation,
            armor,
            credential,
        },
        Arc::new(Progress::default()),
    )
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("notes-世界.txt");
    // Cross multiple authenticated age chunks, including a final partial chunk.
    fs::write(
        &input,
        (0..200_123).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    )
    .unwrap();
    let output = dir.path().join("output");
    fs::create_dir(&output).unwrap();
    let identity = dir.path().join("identity.agekey");
    let public = crypto::generate_identity(&identity).unwrap();
    (dir, input, output, identity, public)
}

#[test]
fn native_keys_binary_and_armor_roundtrip_multiple_chunks() {
    let (dir, input, output, identity, public) = fixture();
    for armor in [false, true] {
        let result = execute(
            &input,
            dir.path(),
            Operation::Encrypt,
            armor,
            Credential::Recipients(public.clone()),
        );
        let encrypted = result[0].output.as_ref().expect("encrypted file");
        assert_ne!(fs::read(&input).unwrap(), fs::read(encrypted).unwrap());
        let restored_dir = output.join(if armor { "armor" } else { "binary" });
        fs::create_dir(&restored_dir).unwrap();
        let result = execute(
            encrypted,
            &restored_dir,
            Operation::Decrypt,
            false,
            Credential::IdentityFile(identity.clone()),
        );
        assert_eq!(
            fs::read(result[0].output.as_ref().unwrap()).unwrap(),
            fs::read(&input).unwrap()
        );
    }
}

#[test]
fn multiple_recipients_can_each_decrypt() {
    let (dir, input, output, first, public) = fixture();
    let second = dir.path().join("second.agekey");
    let second_public = crypto::generate_identity(&second).unwrap();
    let recipients = format!("# my team\n{public}\n\n{second_public}\n");
    let encrypted = execute(
        &input,
        dir.path(),
        Operation::Encrypt,
        false,
        Credential::Recipients(recipients),
    )[0]
    .output
    .clone()
    .unwrap();
    for (i, key) in [first, second].into_iter().enumerate() {
        let target = output.join(i.to_string());
        fs::create_dir(&target).unwrap();
        let result = execute(
            &encrypted,
            &target,
            Operation::Decrypt,
            false,
            Credential::IdentityFile(key),
        );
        assert_eq!(
            fs::read(result[0].output.as_ref().unwrap()).unwrap(),
            fs::read(&input).unwrap()
        );
    }
}

#[test]
fn passphrase_roundtrip_and_wrong_passphrase_never_leaves_plaintext() {
    let (dir, input, output, _, _) = fixture();
    let secret = || {
        Credential::Passphrase(SecretString::from(
            "test-only amber meadow winter orbit".to_owned(),
        ))
    };
    let encrypted = execute(&input, dir.path(), Operation::Encrypt, true, secret())[0]
        .output
        .clone()
        .unwrap();
    let wrong = execute(
        &encrypted,
        &output,
        Operation::Decrypt,
        false,
        Credential::Passphrase(SecretString::from("incorrect".to_owned())),
    );
    assert!(wrong[0].error.is_some());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    let restored = execute(&encrypted, &output, Operation::Decrypt, false, secret());
    assert_eq!(
        fs::read(restored[0].output.as_ref().unwrap()).unwrap(),
        fs::read(&input).unwrap()
    );
}

#[test]
fn corruption_truncation_and_wrong_identity_leave_no_output_or_temporary_file() {
    let (dir, input, output, identity, public) = fixture();
    let encrypted = execute(
        &input,
        dir.path(),
        Operation::Encrypt,
        false,
        Credential::Recipients(public),
    )[0]
    .output
    .clone()
    .unwrap();
    let original = fs::read(&encrypted).unwrap();
    let other = dir.path().join("other.agekey");
    crypto::generate_identity(&other).unwrap();
    let result = execute(
        &encrypted,
        &output,
        Operation::Decrypt,
        false,
        Credential::IdentityFile(other),
    );
    assert!(result[0].error.is_some());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    for truncate in [false, true] {
        let mut corrupt = original.clone();
        if truncate {
            corrupt.truncate(corrupt.len() - 5);
        } else {
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
        }
        fs::write(&encrypted, corrupt).unwrap();
        let result = execute(
            &encrypted,
            &output,
            Operation::Decrypt,
            false,
            Credential::IdentityFile(identity.clone()),
        );
        assert!(result[0].error.is_some());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    }
}

#[test]
fn output_collisions_preserve_original_and_existing_ciphertext() {
    let (dir, input, _, identity, public) = fixture();
    let original = fs::read(&input).unwrap();
    let encrypted = execute(
        &input,
        dir.path(),
        Operation::Encrypt,
        false,
        Credential::Recipients(public.clone()),
    )[0]
    .output
    .clone()
    .unwrap();
    let ciphertext = fs::read(&encrypted).unwrap();
    let second = execute(
        &input,
        dir.path(),
        Operation::Encrypt,
        false,
        Credential::Recipients(public),
    );
    assert!(second[0].error.is_some());
    assert_eq!(fs::read(&encrypted).unwrap(), ciphertext);
    let decrypt = execute(
        &encrypted,
        dir.path(),
        Operation::Decrypt,
        false,
        Credential::IdentityFile(identity),
    );
    assert!(decrypt[0].error.is_some());
    assert_eq!(fs::read(&input).unwrap(), original);
}

#[test]
fn cancelled_job_creates_nothing() {
    let (dir, input, output, _, public) = fixture();
    let progress = Arc::new(Progress::default());
    progress.cancelled.store(true, Ordering::Relaxed);
    let result = crypto::run(
        Job {
            inputs: vec![input],
            output_dir: Some(output.clone()),
            operation: Operation::Encrypt,
            armor: false,
            credential: Credential::Recipients(public),
        },
        progress,
    );
    assert!(result[0].error.as_ref().unwrap().contains("Cancelled"));
    assert_eq!(fs::read_dir(output).unwrap().count(), 0);
    drop(dir);
}

#[test]
fn key_creation_is_parseable_and_never_replaces_a_key() {
    let (dir, _, _, identity, public) = fixture();
    let original = fs::read(&identity).unwrap();
    assert_eq!(crypto::inspect_identity(&identity).unwrap(), vec![public]);
    assert!(crypto::generate_identity(&identity).is_err());
    assert_eq!(fs::read(&identity).unwrap(), original);
    let invalid = dir.path().join("invalid-key");
    fs::write(&invalid, "AGE-SECRET-KEY-invalid-test-value").unwrap();
    let error = crypto::inspect_identity(&invalid).unwrap_err();
    assert!(!error.contains("invalid-test-value"));
}

#[test]
fn batch_reports_each_failure_and_keeps_successful_outputs() {
    let (dir, input, output, _, public) = fixture();
    let result = crypto::run(
        Job {
            inputs: vec![dir.path().join("missing"), input],
            output_dir: Some(output),
            operation: Operation::Encrypt,
            armor: false,
            credential: Credential::Recipients(public),
        },
        Arc::new(Progress::default()),
    );
    assert!(result[0].error.is_some());
    assert!(result[1].output.as_ref().unwrap().is_file());
}

#[test]
fn empty_file_roundtrips_and_invalid_recipient_is_rejected() {
    let (dir, input, output, identity, public) = fixture();
    fs::write(&input, []).unwrap();
    let invalid = execute(
        &input,
        &output,
        Operation::Encrypt,
        false,
        Credential::Recipients("not-a-public-key".into()),
    );
    assert!(invalid[0].error.is_some());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    let encrypted = execute(
        &input,
        dir.path(),
        Operation::Encrypt,
        false,
        Credential::Recipients(public),
    )[0]
    .output
    .clone()
    .unwrap();
    let decrypted = execute(
        &encrypted,
        &output,
        Operation::Decrypt,
        false,
        Credential::IdentityFile(identity),
    );
    assert_eq!(
        fs::metadata(decrypted[0].output.as_ref().unwrap())
            .unwrap()
            .len(),
        0
    );
}

#[test]
#[ignore = "requires official Go age executable in AGE_REFERENCE_BIN"]
fn official_go_age_interoperability_both_directions() {
    let age = std::env::var_os("AGE_REFERENCE_BIN").expect("set AGE_REFERENCE_BIN");
    let (dir, input, output, identity, public) = fixture();
    for armor in [false, true] {
        let encrypted = execute(
            &input,
            dir.path(),
            Operation::Encrypt,
            armor,
            Credential::Recipients(public.clone()),
        )[0]
        .output
        .clone()
        .unwrap();
        let go_restored = output.join(format!("go-{armor}.txt"));
        let result = std::process::Command::new(&age)
            .arg("--decrypt")
            .arg("--identity")
            .arg(&identity)
            .arg("--output")
            .arg(&go_restored)
            .arg(&encrypted)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "reference age rejected desktop ciphertext"
        );
        assert_eq!(fs::read(go_restored).unwrap(), fs::read(&input).unwrap());
        let go_encrypted = dir.path().join(format!("from-go-{armor}.age"));
        let mut command = std::process::Command::new(&age);
        command
            .arg("--encrypt")
            .arg("--recipient")
            .arg(&public)
            .arg("--output")
            .arg(&go_encrypted);
        if armor {
            command.arg("--armor");
        }
        let result = command.arg(&input).output().unwrap();
        assert!(result.status.success());
        let restored = execute(
            &go_encrypted,
            &output,
            Operation::Decrypt,
            false,
            Credential::IdentityFile(identity.clone()),
        );
        assert_eq!(
            fs::read(restored[0].output.as_ref().unwrap()).unwrap(),
            fs::read(&input).unwrap()
        );
    }
    // Validate an independently generated identity as well, without exposing it.
    let generated = age::x25519::Identity::generate();
    let p = dir.path().join("independent.agekey");
    fs::write(&p, generated.to_string().expose_secret()).unwrap();
    assert_eq!(
        crypto::inspect_identity(&p).unwrap(),
        vec![generated.to_public().to_string()]
    );
}
