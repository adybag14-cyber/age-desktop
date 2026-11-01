//! Streaming age operations. Outputs are committed only after authentication and
//! finalization; existing files are never overwritten. No shell or age executable
//! is used by the application.
use age::secrecy::{ExposeSecret, SecretString};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

pub enum Credential {
    Recipients(String),
    Passphrase(SecretString),
    IdentityFile(PathBuf),
}

pub struct Job {
    pub operation: Operation,
    pub inputs: Vec<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub armor: bool,
    pub credential: Credential,
}

#[derive(Default)]
pub struct Progress {
    pub bytes: AtomicU64,
    pub cancelled: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct FileResult {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub error: Option<String>,
}

pub fn recipients(value: &str) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    let mut parsed: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
    for (i, line) in value.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(key) = line.parse::<age::x25519::Recipient>() {
            parsed.push(Box::new(key));
        } else {
            return Err(format!(
                "Recipient on line {} is not a supported age1 X25519 public key.",
                i + 1
            ));
        }
    }
    if parsed.is_empty() {
        return Err("Add at least one recipient public key.".into());
    }
    Ok(parsed)
}

pub fn identity_keys(path: &Path) -> Result<Vec<age::x25519::Identity>> {
    let source = File::open(path).map_err(|e| format!("Cannot open identity file: {e}"))?;
    if source.metadata().map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Identity file is too large (maximum 1 MiB).".into());
    }
    let mut value = Zeroizing::new(String::new());
    source
        .take(1024 * 1024 + 1)
        .read_to_string(&mut value)
        .map_err(|_| "Identity file must contain UTF-8 age secret keys.".to_owned())?;
    if value.len() > 1024 * 1024 {
        return Err("Identity file is too large (maximum 1 MiB).".into());
    }
    let mut keys = Vec::new();
    for line in value
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        keys.push(line.parse::<age::x25519::Identity>().map_err(|_| "This identity file is not a plain X25519 age key file. Encrypted identities, SSH private keys, plugins, and post-quantum keys are not supported in this version.".to_owned())?);
    }
    if keys.is_empty() {
        return Err("No age secret keys found in this file.".into());
    }
    Ok(keys)
}

pub fn output_path(
    input: &Path,
    dir: Option<&Path>,
    operation: Operation,
    armor: bool,
) -> Result<PathBuf> {
    let name = input.file_name().ok_or("Input has no filename.")?;
    let name = match operation {
        Operation::Encrypt => {
            let mut name = name.to_os_string();
            name.push(if armor { ".age.txt" } else { ".age" });
            name
        }
        Operation::Decrypt => {
            // Only strip known extensions. Never allow a filename stored in the
            // encrypted data to influence the destination.
            let as_path = Path::new(name);
            if name.to_string_lossy().ends_with(".age.txt") {
                Path::new(as_path.file_stem().unwrap())
                    .file_stem()
                    .unwrap()
                    .to_os_string()
            } else if as_path.extension().is_some_and(|ext| ext == "age") {
                as_path.file_stem().unwrap().to_os_string()
            } else {
                let mut name = name.to_os_string();
                name.push(".decrypted");
                name
            }
        }
    };
    Ok(dir
        .unwrap_or_else(|| input.parent().unwrap_or(Path::new(".")))
        .join(name))
}

fn copy_stream(reader: &mut impl Read, writer: &mut impl Write, progress: &Progress) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        if progress.cancelled.load(Ordering::Relaxed) {
            return Err("Cancelled. No output was saved for this file.".into());
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|e| format!("Cannot read or authenticate file: {e}"))?;
        if count == 0 {
            return Ok(());
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|e| format!("Cannot write output: {e}"))?;
        progress.bytes.fetch_add(count as u64, Ordering::Relaxed);
    }
}

fn transform(input: &Path, output: &Path, job: &Job, progress: &Progress) -> Result<()> {
    if progress.cancelled.load(Ordering::Relaxed) {
        return Err("Cancelled. No output was saved for this file.".into());
    }
    // persist_noclobber below is also required: this preliminary check alone
    // would have a race with another process creating the destination.
    if output.exists() {
        return Err("Output already exists. Choose another output folder; existing files are never replaced.".into());
    }
    let source = File::open(input).map_err(|e| format!("Cannot open input: {e}"))?;
    if !source.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Choose a regular file. Archive folders before encrypting.".into());
    }
    let parent = output.parent().unwrap_or(Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".age-desktop-")
        .tempfile_in(parent)
        .map_err(|e| format!("Cannot create output in selected folder: {e}"))?;
    if job.operation == Operation::Decrypt {
        crate::private_file::restrict(temp.path())
            .map_err(|e| format!("Cannot protect the decrypted output file: {e}"))?;
    }
    {
        let mut destination = BufWriter::with_capacity(64 * 1024, temp.as_file_mut());
        match job.operation {
            Operation::Encrypt => {
                let keys;
                let encryptor = match &job.credential {
                    Credential::Recipients(value) => {
                        keys = recipients(value)?;
                        age::Encryptor::with_recipients(
                            keys.iter().map(|r| r.as_ref() as &dyn age::Recipient),
                        )
                        .map_err(|e| e.to_string())?
                    }
                    Credential::Passphrase(passphrase) => {
                        if passphrase.expose_secret().is_empty() {
                            return Err("Enter a passphrase.".into());
                        }
                        age::Encryptor::with_user_passphrase(passphrase.clone())
                    }
                    _ => {
                        return Err("Encryption requires public recipients or a passphrase.".into());
                    }
                };
                let format = if job.armor {
                    age::armor::Format::AsciiArmor
                } else {
                    age::armor::Format::Binary
                };
                let armor = age::armor::ArmoredWriter::wrap_output(&mut destination, format)
                    .map_err(|e| e.to_string())?;
                let mut writer = encryptor.wrap_output(armor).map_err(|e| e.to_string())?;
                copy_stream(&mut BufReader::new(source), &mut writer, progress)?;
                writer
                    .finish()
                    .map_err(|e| e.to_string())?
                    .finish()
                    .map_err(|e| e.to_string())?;
            }
            Operation::Decrypt => {
                let armor = age::armor::ArmoredReader::new(BufReader::new(source));
                let decryptor = age::Decryptor::new(armor)
                    .map_err(|e| format!("Not a supported age file: {e}"))?;
                let keys;
                let password;
                let identities: Vec<&dyn age::Identity> = match &job.credential {
                    Credential::IdentityFile(path) => {
                        if decryptor.is_scrypt() {
                            return Err(
                                "This file uses a passphrase. Select Passphrase to unlock it."
                                    .into(),
                            );
                        }
                        keys = identity_keys(path)?;
                        keys.iter().map(|key| key as &dyn age::Identity).collect()
                    }
                    Credential::Passphrase(passphrase) => {
                        if !decryptor.is_scrypt() {
                            return Err("This file uses a recipient key. Select Identity file to unlock it.".into());
                        }
                        password = age::scrypt::Identity::new(passphrase.clone());
                        vec![&password]
                    }
                    _ => return Err("Decryption requires an identity file or passphrase.".into()),
                };
                let mut reader = decryptor
                    .decrypt(identities.into_iter())
                    .map_err(|e| format!("Unable to unlock file: {e}"))?;
                copy_stream(&mut reader, &mut destination, progress)?;
            }
        }
        destination.flush().map_err(|e| e.to_string())?;
    }
    if progress.cancelled.load(Ordering::Relaxed) {
        return Err("Cancelled. No output was saved for this file.".into());
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    temp.persist_noclobber(output).map_err(|e| {
        format!(
            "Cannot save output without replacing an existing file: {}",
            e.error
        )
    })?;
    Ok(())
}

pub fn run(job: Job, progress: Arc<Progress>) -> Vec<FileResult> {
    job.inputs
        .iter()
        .map(|input| {
            let result = output_path(input, job.output_dir.as_deref(), job.operation, job.armor)
                .and_then(|output| transform(input, &output, &job, &progress).map(|()| output));
            match result {
                Ok(output) => FileResult {
                    input: input.clone(),
                    output: Some(output),
                    error: None,
                },
                Err(error) => FileResult {
                    input: input.clone(),
                    output: None,
                    error: Some(error),
                },
            }
        })
        .collect()
}

/// Generate directly into an explicit user-chosen file. Secret material never
/// needs to be displayed or copied to the clipboard.
pub fn generate_identity(path: &Path) -> Result<String> {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let mut file = tempfile::Builder::new()
        .prefix(".age-key-")
        .tempfile_in(path.parent().unwrap_or(Path::new(".")))
        .map_err(|e| e.to_string())?;
    crate::private_file::restrict(file.path())
        .map_err(|e| format!("Cannot protect the secret identity file: {e}"))?;
    writeln!(
        file,
        "# Created by age desktop\n# public key: {recipient}\n{}",
        identity.to_string().expose_secret()
    )
    .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist_noclobber(path).map_err(|e| {
        format!(
            "Cannot save identity (existing files are never replaced): {}",
            e.error
        )
    })?;
    Ok(recipient)
}

pub fn inspect_identity(path: &Path) -> Result<Vec<String>> {
    Ok(identity_keys(path)?
        .iter()
        .map(|key| key.to_public().to_string())
        .collect())
}

pub fn file_size(path: &Path) -> Result<u64> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("Folders are not supported. Create an archive first.".into());
    }
    Ok(metadata.len())
}
