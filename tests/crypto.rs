use age_desktop::{
    crypto::{self, Job, Operation},
    engine::{self, Progress, Request, Response},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn key(dir: &Path, kind: &str, protected: bool) -> (PathBuf, String) {
    let path = dir.join(format!(
        "{kind}-{}.agekey",
        if protected { "protected" } else { "plain" }
    ));
    let mut r = Request::new("generate_key");
    r.key_kind = kind.into();
    r.protect_key = protected;
    r.passphrase = "fixture-only meadow lantern comet river".into();
    let result = crypto::generate_identity(&path, r, Arc::new(Progress::default())).unwrap();
    (path, result.public_keys[0].clone())
}
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let input = d.path().join("notes-世界.bin");
    fs::write(
        &input,
        (0..200123).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    )
    .unwrap();
    let output = d.path().join("output");
    fs::create_dir(&output).unwrap();
    (d, input, output)
}
fn job(input: &Path, out: &Path, operation: Operation, request: Request) -> Job {
    Job {
        operation,
        inputs: vec![input.to_owned()],
        output_dir: Some(out.to_owned()),
        output_file: None,
        overwrite: false,
        request,
    }
}
fn enc(public: &str, armor: bool) -> Request {
    let mut r = Request::new("encrypt");
    r.recipients = public.into();
    r.armor = armor;
    r
}
fn dec(identity: &Path) -> Request {
    let mut r = Request::new("decrypt");
    r.identity_files = vec![identity.to_str().unwrap().into()];
    r
}
fn run(job: Job) -> Vec<crypto::FileResult> {
    crypto::run(job, Arc::new(Progress::default()))
}
fn with_replies<T>(f: impl FnOnce(Arc<Progress>) -> T) -> T {
    let p = Arc::new(Progress::default());
    let done = Arc::new(AtomicBool::new(false));
    let responder = {
        let p = p.clone();
        let done = done.clone();
        thread::spawn(move || {
            let mut last = 0;
            let deadline = Instant::now() + Duration::from_secs(30);
            while !done.load(Ordering::Acquire) {
                if Instant::now() > deadline {
                    p.cancel();
                    break;
                }
                let prompt = p.prompt.lock().unwrap().clone();
                if let Some(prompt) = prompt
                    && prompt.id != last
                {
                    last = prompt.id;
                    let value = if !prompt.yes.is_empty() {
                        "yes"
                    } else if prompt.message.contains("Test PIN") {
                        "fixture-pin"
                    } else {
                        "fixture-only meadow lantern comet river"
                    };
                    p.respond(prompt.id, value.into(), false);
                }
                thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let result = f(p);
    done.store(true, Ordering::Release);
    responder.join().unwrap();
    result
}
fn success(result: &[crypto::FileResult]) -> PathBuf {
    result[0]
        .output
        .clone()
        .unwrap_or_else(|| panic!("operation failed: {:?}", result[0].error))
}

#[test]
fn official_engine_reports_pinned_version() {
    let r = crypto::confirm_engine().unwrap();
    assert!(r.engine.contains("age 1.3.2"));
    assert!(r.go.starts_with("go1.27"));
}

#[test]
fn classic_and_quantum_binary_and_armor_multichunk_roundtrips() {
    for kind in ["classic", "pq"] {
        let (d, input, out) = fixture();
        let (id, pubkey) = key(d.path(), kind, false);
        for armor in [false, true] {
            let target = out.join(if armor { "armor" } else { "binary" });
            fs::create_dir(&target).unwrap();
            let encrypted = success(&run(job(
                &input,
                &target,
                Operation::Encrypt,
                enc(&pubkey, armor),
            )));
            let restored = success(&run(job(&encrypted, &out, Operation::Decrypt, dec(&id))));
            assert!(crypto::same_contents(&input, &restored).unwrap());
            fs::remove_file(restored).unwrap();
        }
    }
}

#[test]
fn protected_quantum_identity_prompts_over_private_pipe() {
    let (d, input, out) = fixture();
    let (id, pubkey) = key(d.path(), "pq", true);
    let encrypted = success(&run(job(
        &input,
        d.path(),
        Operation::Encrypt,
        enc(&pubkey, true),
    )));
    let result =
        with_replies(|p| crypto::run(job(&encrypted, &out, Operation::Decrypt, dec(&id)), p));
    assert!(crypto::same_contents(&input, &success(&result)).unwrap());
    let mut export = Request::new("public_keys");
    export.identity_files.push(id.to_str().unwrap().into());
    let result = with_replies(|p| engine::run(&export, p)).unwrap();
    assert_eq!(result.public_keys, vec![pubkey]);
}

#[test]
fn recipients_files_multiple_identities_and_self_encryption() {
    let (d, input, out) = fixture();
    let (id, public) = key(d.path(), "classic", false);
    let otherdir = d.path().join("other");
    fs::create_dir(&otherdir).unwrap();
    let (wrong, _) = key(&otherdir, "classic", false);
    let recipients = d.path().join("recipients.txt");
    fs::write(&recipients, format!("# self\n{public}\n")).unwrap();
    let mut r = Request::new("encrypt");
    r.recipient_files.push(recipients.to_str().unwrap().into());
    let encrypted = success(&run(job(&input, d.path(), Operation::Encrypt, r)));
    let mut r = dec(&wrong);
    r.identity_files.push(id.to_str().unwrap().into());
    assert!(
        crypto::same_contents(
            &input,
            &success(&run(job(&encrypted, &out, Operation::Decrypt, r)))
        )
        .unwrap()
    );
    let mut r = Request::new("encrypt");
    r.identity_files.push(id.to_str().unwrap().into());
    r.text = Some("encrypt to myself".into());
    let ciphertext = engine::run(&r, Arc::new(Progress::default())).unwrap();
    let mut r = dec(&id);
    r.text = ciphertext.text.clone();
    assert_eq!(
        engine::run(&r, Arc::new(Progress::default()))
            .unwrap()
            .text
            .as_deref(),
        Some("encrypt to myself")
    );
}

#[test]
fn passphrase_text_roundtrip_and_automatic_prompt() {
    let mut r = Request::new("encrypt");
    r.protection = "passphrase".into();
    r.passphrase = "fixture-only meadow lantern comet river".into();
    r.text = Some("A private note ✓".into());
    let encrypted = engine::run(&r, Arc::new(Progress::default())).unwrap();
    let mut r = Request::new("decrypt");
    r.text = encrypted.text.clone();
    let result = with_replies(|p| engine::run(&r, p)).unwrap();
    assert_eq!(result.text.as_deref(), Some("A private note ✓"));
    r.passphrase = "wrong".into();
    assert!(engine::run(&r, Arc::new(Progress::default())).is_err());
}

#[test]
fn wrong_key_corruption_and_truncation_preserve_existing_output() {
    let (d, input, out) = fixture();
    let (id, public) = key(d.path(), "classic", false);
    let encrypted = success(&run(job(
        &input,
        d.path(),
        Operation::Encrypt,
        enc(&public, false),
    )));
    let original = fs::read(&encrypted).unwrap();
    let target = out.join(input.file_name().unwrap());
    fs::write(&target, b"preserve this output").unwrap();
    let other = d.path().join("other");
    fs::create_dir(&other).unwrap();
    let (wrong, _) = key(&other, "classic", false);
    let mut request = job(&encrypted, &out, Operation::Decrypt, dec(&wrong));
    request.overwrite = true;
    assert!(run(request)[0].error.is_some());
    for truncate in [false, true] {
        let mut bad = original.clone();
        if truncate {
            bad.truncate(bad.len() - 7);
        } else {
            let end = bad.len() - 1;
            bad[end] ^= 1;
        }
        fs::write(&encrypted, bad).unwrap();
        let mut request = job(&encrypted, &out, Operation::Decrypt, dec(&id));
        request.overwrite = true;
        assert!(run(request)[0].error.is_some());
        assert_eq!(fs::read(&target).unwrap(), b"preserve this output");
        assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    }
}

#[test]
fn explicit_output_and_overwrite_never_replace_sources_or_keys() {
    let (d, input, out) = fixture();
    let (id, public) = key(d.path(), "classic", false);
    let mut request = job(&input, &out, Operation::Encrypt, enc(&public, false));
    let named = out.join("custom-name.age");
    request.output_file = Some(named.clone());
    let encrypted = success(&run(request));
    assert_eq!(encrypted, named);
    let first = fs::read(&named).unwrap();
    let mut repeat = job(&input, &out, Operation::Encrypt, enc(&public, false));
    repeat.output_file = Some(named.clone());
    assert!(run(repeat)[0].error.is_some());
    assert_eq!(fs::read(&named).unwrap(), first);
    let mut replace = job(&input, &out, Operation::Encrypt, enc(&public, false));
    replace.output_file = Some(named.clone());
    replace.overwrite = true;
    success(&run(replace));
    assert_ne!(fs::read(&named).unwrap(), first);
    for target in [&input, &id] {
        let original = fs::read(target).unwrap();
        let mut unsafe_job = job(&input, &out, Operation::Encrypt, enc(&public, false));
        unsafe_job
            .request
            .identity_files
            .push(id.to_str().unwrap().into());
        unsafe_job.output_file = Some(target.clone());
        unsafe_job.overwrite = true;
        assert!(run(unsafe_job)[0].error.is_some());
        assert_eq!(fs::read(target).unwrap(), original);
    }
}

#[test]
fn hard_link_output_cannot_replace_source() {
    let (d, input, out) = fixture();
    let (_, public) = key(d.path(), "classic", false);
    let linked = out.join("linked-output");
    fs::hard_link(&input, &linked).unwrap();
    let mut request = job(&input, &out, Operation::Encrypt, enc(&public, false));
    request.output_file = Some(linked);
    request.overwrite = true;
    assert!(run(request)[0].error.is_some());
}

#[test]
fn cancel_waiting_for_password_cleans_temp_file() {
    let (d, input, out) = fixture();
    let mut r = Request::new("encrypt");
    r.protection = "passphrase".into();
    r.passphrase = "fixture-only meadow lantern comet river".into();
    let encrypted = success(&run(job(&input, d.path(), Operation::Encrypt, r)));
    let p = Arc::new(Progress::default());
    let worker = {
        let p = p.clone();
        let out = out.clone();
        thread::spawn(move || {
            crypto::run(
                job(
                    &encrypted,
                    &out,
                    Operation::Decrypt,
                    Request::new("decrypt"),
                ),
                p,
            )
        })
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    while p.prompt.lock().unwrap().is_none() {
        assert!(Instant::now() < deadline, "password prompt did not arrive");
        thread::sleep(Duration::from_millis(10));
    }
    p.cancel();
    assert!(
        worker.join().unwrap()[0]
            .error
            .as_ref()
            .unwrap()
            .contains("Cancelled")
    );
    assert_eq!(fs::read_dir(out).unwrap().count(), 0);
}

#[test]
fn key_creation_never_overwrites_and_private_key_is_not_returned() {
    let (d, _, _) = fixture();
    let (path, public) = key(d.path(), "pq", false);
    let original = fs::read(&path).unwrap();
    let r = Request::new("generate_key");
    assert!(crypto::generate_identity(&path, r, Arc::new(Progress::default())).is_err());
    assert_eq!(fs::read(path).unwrap(), original);
    assert!(public.starts_with("age1pq1"));
    assert!(!public.contains("SECRET"));
}

#[test]
fn empty_files_and_partial_batch_results() {
    let (d, input, out) = fixture();
    fs::write(&input, []).unwrap();
    let (id, public) = key(d.path(), "classic", false);
    let mut batch = job(&input, &out, Operation::Encrypt, enc(&public, false));
    batch.inputs.insert(0, d.path().join("missing"));
    let result = run(batch);
    assert!(result[0].error.is_some());
    let encrypted = result[1].output.as_ref().unwrap();
    let restored = success(&run(job(encrypted, &out, Operation::Decrypt, dec(&id))));
    assert_eq!(fs::metadata(restored).unwrap().len(), 0);
}

#[test]
fn inspection_returns_metadata_without_plaintext() {
    let (d, input, _) = fixture();
    fs::write(&input, "distinct private payload marker").unwrap();
    let (_, public) = key(d.path(), "pq", false);
    let encrypted = success(&run(job(
        &input,
        d.path(),
        Operation::Encrypt,
        enc(&public, false),
    )));
    let mut r = Request::new("inspect");
    r.input = encrypted.to_str().unwrap().into();
    let result = engine::run(&r, Arc::new(Progress::default())).unwrap();
    let metadata = result.metadata.as_ref().unwrap();
    assert_eq!(metadata["postquantum"], "yes");
    assert!(!metadata.to_string().contains("private payload"));
    assert!(result.text.is_none());
}

fn plugin_fixture() -> tempfile::TempDir {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/testplugin/age-plugin-desktoptest.exe");
    assert!(
        source.is_file(),
        "run scripts/build-engine.ps1 -Tests first"
    );
    let dir = tempfile::tempdir().unwrap();
    fs::copy(source, dir.path().join("age-plugin-desktoptest.exe")).unwrap();
    dir
}
#[test]
fn plugin_secret_confirmation_identity_and_recipient_workflows() {
    let plugin = plugin_fixture();
    let mut r = Request::new("encrypt");
    r.protection = "plugin".into();
    r.plugins = vec!["desktoptest".into()];
    r.plugin_dir = plugin.path().to_str().unwrap().into();
    r.text = Some("plugin protocol payload".into());
    let encrypted = with_replies(|p| engine::run(&r, p)).unwrap();
    r.operation = "decrypt".into();
    r.text = encrypted.text.clone();
    let decrypted = with_replies(|p| engine::run(&r, p)).unwrap();
    assert_eq!(decrypted.text.as_deref(), Some("plugin protocol payload"));
    let public = std::process::Command::new(plugin.path().join("age-plugin-desktoptest.exe"))
        .arg("--recipient")
        .output()
        .unwrap();
    assert!(public.status.success());
    r.operation = "encrypt".into();
    r.recipients = String::from_utf8(public.stdout).unwrap();
    r.plugins.clear();
    r.text = Some("recipient plugin path".into());
    assert!(with_replies(|p| engine::run(&r, p)).is_ok());
}

#[cfg(windows)]
#[test]
fn cancelling_plugin_prompt_terminates_exact_owned_plugin_process() {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    let plugin = plugin_fixture();
    let mut r = Request::new("encrypt");
    r.protection = "plugin".into();
    r.plugins = vec!["desktoptest".into()];
    r.plugin_dir = plugin.path().to_str().unwrap().into();
    r.text = Some("cancel fixture".into());
    let p = Arc::new(Progress::default());
    let worker = {
        let p = p.clone();
        thread::spawn(move || engine::run(&r, p))
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    while p.prompt.lock().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let pid: u32 = fs::read_to_string(plugin.path().join("plugin.pid"))
        .unwrap()
        .parse()
        .unwrap();
    // Open a handle while the exact fixture process is still alive. Waiting on
    // this handle cannot confuse a recycled PID with the owned plugin.
    unsafe {
        let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        assert!(!process.is_null());
        p.cancel();
        assert!(worker.join().unwrap().is_err());
        assert_eq!(WaitForSingleObject(process, 5000), WAIT_OBJECT_0);
        CloseHandle(process);
    }
}

#[test]
fn mode_selection_rejects_wrong_key_type() {
    let (d, _, _) = fixture();
    let (_, public) = key(d.path(), "classic", false);
    let mut r = enc(&public, false);
    r.protection = "pq".into();
    r.text = Some("must not silently use classic".into());
    assert!(engine::run(&r, Arc::new(Progress::default())).is_err());
}

#[test]
fn binary_decryption_is_not_silently_converted_to_text() {
    let (d, input, _) = fixture();
    let (id, public) = key(d.path(), "pq", false);
    let encrypted = success(&run(job(
        &input,
        d.path(),
        Operation::Encrypt,
        enc(&public, true),
    )));
    let mut r = dec(&id);
    r.text = Some(fs::read_to_string(encrypted).unwrap());
    assert!(engine::run(&r, Arc::new(Progress::default())).is_err());
}

#[test]
fn public_errors_do_not_echo_secret_identity() {
    let mut r = Request::new("encrypt");
    r.recipients = "AGE-SECRET-KEY-sensitive-fixture".into();
    r.text = Some("fixture".into());
    let error = match engine::run(&r, Arc::new(Progress::default())) {
        Ok(Response { .. }) => panic!("invalid recipient accepted"),
        Err(e) => e,
    };
    assert!(!error.contains("sensitive-fixture"));
}
