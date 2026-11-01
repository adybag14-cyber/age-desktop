//! Typed, bounded stdio protocol for the pinned official age engine adapter.
//! Secrets travel in pipes, never command arguments, environment variables, or logs.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Serialize)]
pub struct Request {
    pub protocol: u32,
    pub operation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub input: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub protection: String,
    pub recipients: String,
    pub recipient_files: Vec<String>,
    pub identity_files: Vec<String>,
    pub identity_text: String,
    pub plugins: Vec<String>,
    pub plugin_dir: String,
    pub passphrase: String,
    pub armor: bool,
    pub key_kind: String,
    pub protect_key: bool,
}
impl Default for Request {
    fn default() -> Self {
        Self {
            protocol: 1,
            operation: String::new(),
            input: String::new(),
            output: String::new(),
            text: None,
            protection: "auto".into(),
            recipients: String::new(),
            recipient_files: vec![],
            identity_files: vec![],
            identity_text: String::new(),
            plugins: vec![],
            plugin_dir: String::new(),
            passphrase: String::new(),
            armor: false,
            key_kind: "classic".into(),
            protect_key: false,
        }
    }
}
impl Request {
    pub fn new(operation: &str) -> Self {
        let mut request = Self::default();
        request.operation = operation.into();
        request
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        self.identity_text.zeroize();
        if let Some(text) = &mut self.text {
            text.zeroize();
        }
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub public_keys: Vec<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub go: String,
}
impl Drop for Response {
    fn drop(&mut self) {
        if let Some(text) = &mut self.text {
            text.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct Prompt {
    pub id: u64,
    pub message: String,
    pub secret: bool,
    pub yes: String,
    pub no: String,
}
struct Reply {
    id: u64,
    value: Zeroizing<String>,
    cancel: bool,
}
#[derive(Default)]
pub struct Progress {
    pub bytes: AtomicU64,
    pub cancelled: AtomicBool,
    pub status: Mutex<String>,
    pub prompt: Mutex<Option<Prompt>>,
    next_prompt: AtomicU64,
    replies: Mutex<VecDeque<Reply>>,
}
impl Progress {
    pub fn respond(&self, id: u64, value: String, cancel: bool) {
        self.replies.lock().unwrap().push_back(Reply {
            id,
            value: Zeroizing::new(value),
            cancel,
        });
        let mut prompt = self.prompt.lock().unwrap();
        if prompt.as_ref().is_some_and(|p| p.id == id) {
            *prompt = None;
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        *self.prompt.lock().unwrap() = None;
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGE_DESKTOP_ENGINE") {
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_file() {
            return Err(
                "AGE_DESKTOP_ENGINE must name an existing absolute executable path.".into(),
            );
        }
        return Ok(path);
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut parent = executable
        .parent()
        .ok_or("Application location is unavailable")?;
    if parent.file_name().is_some_and(|s| s == "deps") {
        parent = parent.parent().ok_or("Build location is unavailable")?;
    }
    let candidate = parent.join(if cfg!(windows) {
        "age-engine.exe"
    } else {
        "age-engine"
    });
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err("The age engine is missing. Keep the complete portable package together, or run scripts/build.ps1 when building from source.".into())
}

pub fn run(request: &Request, progress: Arc<Progress>) -> Result<Response> {
    if progress.is_cancelled() {
        return Err("Cancelled.".into());
    }
    let mut command = Command::new(path()?);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("AGEDEBUG");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot start age engine: {e}"))?;
    let job = match crate::owned_process::Job::attach(&child) {
        Ok(job) => Arc::new(job),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Cannot supervise engine process: {e}"));
        }
    };
    let mut input = child
        .stdin
        .take()
        .ok_or("Engine input pipe is unavailable")?;
    let mut output = BufReader::new(
        child
            .stdout
            .take()
            .ok_or("Engine output pipe is unavailable")?,
    );
    let child = Arc::new(Mutex::new(child));
    let done = Arc::new(AtomicBool::new(false));
    let monitor = {
        let child = child.clone();
        let done = done.clone();
        let progress = progress.clone();
        let job = job.clone();
        thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                if progress.is_cancelled() {
                    job.terminate();
                    let _ = child.lock().unwrap().kill();
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        })
    };
    let base = progress.bytes.load(Ordering::Relaxed);
    let result = (|| {
        let mut encoded = Zeroizing::new(serde_json::to_vec(request).map_err(|e| e.to_string())?);
        encoded.push(b'\n');
        input.write_all(&encoded).map_err(|e| e.to_string())?;
        input.flush().map_err(|e| e.to_string())?;
        encoded.zeroize();
        loop {
            let mut line = Zeroizing::new(Vec::new());
            let count = Read::take(&mut output, 16 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|e| e.to_string())?;
            if count == 0 {
                return Err(if progress.is_cancelled() {
                    "Cancelled."
                } else {
                    "The age engine stopped before completing the operation."
                }
                .into());
            }
            if count > 16 * 1024 * 1024 {
                return Err("Engine response exceeded the protocol limit.".into());
            }
            let value: serde_json::Value = serde_json::from_slice(&line)
                .map_err(|_| "Invalid age engine response".to_owned())?;
            match value.get("type").and_then(|s| s.as_str()) {
                Some("result") => {
                    return serde_json::from_value(value)
                        .map_err(|_| "Invalid age engine result".into());
                }
                Some("error") => {
                    return Err(value["message"]
                        .as_str()
                        .unwrap_or("Age operation failed")
                        .to_owned());
                }
                Some("progress") => {
                    if let Some(bytes) = value["bytes"].as_u64() {
                        progress
                            .bytes
                            .store(base.saturating_add(bytes), Ordering::Relaxed);
                    }
                }
                Some("status") => {
                    *progress.status.lock().unwrap() =
                        value["message"].as_str().unwrap_or_default().to_owned()
                }
                Some("prompt") => {
                    let local = progress.next_prompt.fetch_add(1, Ordering::Relaxed) + 1;
                    let remote = value["prompt_id"].as_u64().ok_or("Invalid engine prompt")?;
                    *progress.prompt.lock().unwrap() = Some(Prompt {
                        id: local,
                        message: value["message"]
                            .as_str()
                            .unwrap_or("Input required")
                            .to_owned(),
                        secret: value["secret"].as_bool().unwrap_or(false),
                        yes: value["yes"].as_str().unwrap_or_default().to_owned(),
                        no: value["no"].as_str().unwrap_or_default().to_owned(),
                    });
                    let reply = loop {
                        if progress.is_cancelled() {
                            return Err("Cancelled.".into());
                        }
                        let reply = progress.replies.lock().unwrap().pop_front();
                        if let Some(reply) = reply
                            && reply.id == local
                        {
                            break reply;
                        }
                        thread::sleep(Duration::from_millis(25));
                    };
                    let mut encoded=Zeroizing::new(serde_json::to_vec(&serde_json::json!({"prompt_id":remote,"value":reply.value.as_str(),"cancel":reply.cancel})).map_err(|e|e.to_string())?);
                    encoded.push(b'\n');
                    input.write_all(&encoded).map_err(|e| e.to_string())?;
                    input.flush().map_err(|e| e.to_string())?;
                    *progress.prompt.lock().unwrap() = None;
                }
                _ => return Err("Unknown age engine event".into()),
            }
        }
    })();
    *progress.prompt.lock().unwrap() = None;
    if result.is_err() {
        job.terminate();
        let _ = child.lock().unwrap().kill();
    }
    done.store(true, Ordering::Release);
    let _ = monitor.join();
    drop(input);
    let exit = child.lock().unwrap().wait().map_err(|e| e.to_string())?;
    if progress.is_cancelled() {
        return Err("Cancelled.".into());
    }
    if result.is_ok() && !exit.success() {
        return Err("The age engine exited unsuccessfully.".into());
    }
    result
}
