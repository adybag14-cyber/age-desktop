//! Output safety and batch orchestration. The official age engine implements
//! cryptography; Rust owns destinations, permissions, cancellation, and commit.
pub use crate::engine::Progress;
use crate::engine::{self, Request, Response};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

pub type Result<T> = std::result::Result<T, String>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}
impl Operation {
    pub fn name(self) -> &'static str {
        if self == Self::Encrypt {
            "encrypt"
        } else {
            "decrypt"
        }
    }
}
pub struct Job {
    pub operation: Operation,
    pub inputs: Vec<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub overwrite: bool,
    pub request: Request,
}
#[derive(Debug, Clone)]
pub struct FileResult {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub error: Option<String>,
}

pub fn output_path(
    input: &Path,
    dir: Option<&Path>,
    operation: Operation,
    armor: bool,
) -> Result<PathBuf> {
    let name = input.file_name().ok_or("Input has no filename")?;
    let name = match operation {
        Operation::Encrypt => {
            let mut n = name.to_os_string();
            n.push(if armor { ".age.txt" } else { ".age" });
            n
        }
        Operation::Decrypt => {
            let p = Path::new(name);
            if name.to_string_lossy().ends_with(".age.txt") {
                Path::new(p.file_stem().ok_or("Invalid filename")?)
                    .file_stem()
                    .ok_or("Invalid filename")?
                    .to_os_string()
            } else if p.extension().is_some_and(|s| s == "age") {
                p.file_stem().ok_or("Invalid filename")?.to_os_string()
            } else {
                let mut n = name.to_os_string();
                n.push(".decrypted");
                n
            }
        }
    };
    Ok(dir
        .unwrap_or_else(|| input.parent().unwrap_or(Path::new(".")))
        .join(name))
}
pub fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "This path cannot be represented as UTF-8.".into())
}
pub fn file_size(path: &Path) -> Result<u64> {
    let m = fs::metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() {
        return Err("Archive folders first; choose regular files here.".into());
    }
    Ok(m.len())
}

fn staging(path: &Path, private: bool) -> Result<tempfile::NamedTempFile> {
    let temp = tempfile::Builder::new()
        .prefix(".age-desktop-")
        .tempfile_in(path.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("Cannot create output in this folder: {e}"))?;
    if private {
        crate::private_file::restrict(temp.path())
            .map_err(|e| format!("Cannot protect the output: {e}"))?;
    }
    Ok(temp)
}
fn commit(temp: tempfile::NamedTempFile, target: &Path, overwrite: bool) -> Result<()> {
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    if overwrite {
        temp.persist(target)
            .map_err(|e| format!("Cannot replace output: {}", e.error))?;
    } else {
        temp.persist_noclobber(target).map_err(|e| {
            format!(
                "Cannot save output; existing files are preserved: {}",
                e.error
            )
        })?;
    }
    Ok(())
}
fn transform(input: &Path, target: &Path, job: &Job, progress: Arc<Progress>) -> Result<()> {
    if progress.is_cancelled() {
        return Err("Cancelled.".into());
    }
    file_size(input)?;
    if target.exists() {
        let key_collision = job
            .request
            .identity_files
            .iter()
            .chain(job.request.recipient_files.iter())
            .any(|p| same_file::is_same_file(p, target).unwrap_or(false));
        if key_collision
            || job
                .inputs
                .iter()
                .any(|p| same_file::is_same_file(p, target).unwrap_or(false))
        {
            return Err("An output would replace one of your source files. Choose a different name or folder.".into());
        }
        if !job.overwrite {
            return Err("Output already exists. Choose another name/folder, or explicitly allow replacement.".into());
        }
    }
    let temp = staging(target, job.operation == Operation::Decrypt)?;
    let mut request = job.request.clone();
    request.operation = job.operation.name().into();
    request.input = path_string(input)?;
    request.output = path_string(temp.path())?;
    request.text = None;
    engine::run(&request, progress.clone())?;
    if progress.is_cancelled() {
        return Err("Cancelled. The incomplete output was removed.".into());
    }
    commit(temp, target, job.overwrite)
}
pub fn run(job: Job, progress: Arc<Progress>) -> Vec<FileResult> {
    if job.output_file.is_some() && job.inputs.len() != 1 {
        return vec![FileResult {
            input: PathBuf::from("Output"),
            output: None,
            error: Some("Save as a filename is available for one input file at a time.".into()),
        }];
    }
    job.inputs
        .iter()
        .map(|input| {
            let target = match &job.output_file {
                Some(p) => Ok(p.clone()),
                None => output_path(
                    input,
                    job.output_dir.as_deref(),
                    job.operation,
                    job.request.armor,
                ),
            };
            let result =
                target.and_then(|p| transform(input, &p, &job, progress.clone()).map(|()| p));
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
pub fn generate_identity(
    path: &Path,
    request: Request,
    progress: Arc<Progress>,
) -> Result<Response> {
    if path.exists() {
        return Err("Choose a new identity filename. Existing keys are never replaced.".into());
    }
    let temp = staging(path, true)?;
    let mut request = request;
    request.operation = "generate_key".into();
    request.output = path_string(temp.path())?;
    let result = engine::run(&request, progress.clone())?;
    if progress.is_cancelled() {
        return Err("Cancelled.".into());
    }
    commit(temp, path, false)?;
    Ok(result)
}
pub fn save_text(path: &Path, text: &str, private: bool) -> Result<()> {
    let mut temp = staging(path, private)?;
    temp.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    commit(temp, path, false)
}
pub fn confirm_engine() -> Result<Response> {
    engine::run(&Request::new("version"), Arc::new(Progress::default()))
}
pub fn same_contents(a: &Path, b: &Path) -> Result<bool> {
    use std::io::Read;
    let mut a = File::open(a).map_err(|e| e.to_string())?;
    let mut b = File::open(b).map_err(|e| e.to_string())?;
    if a.metadata().map_err(|e| e.to_string())?.len()
        != b.metadata().map_err(|e| e.to_string())?.len()
    {
        return Ok(false);
    }
    let mut x = [0u8; 8192];
    let mut y = [0u8; 8192];
    loop {
        let n = a.read(&mut x).map_err(|e| e.to_string())?;
        let m = b.read(&mut y).map_err(|e| e.to_string())?;
        if n != m || x[..n] != y[..m] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}
