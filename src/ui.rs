mod views;
use crate::Options;
use age_desktop::{
    crypto::{self, FileResult, Job, Operation},
    engine::{self, Progress, Prompt, Request, Response},
};
use iced::{Element, Subscription, Task, Theme, window};
use shadcn_iced::{self as shad, Mode};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Encrypt,
    Decrypt,
    Keys,
    Inspect,
    Settings,
    Guide,
}
impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Keys => "Your keys",
            Self::Inspect => "Inspect a file",
            Self::Settings => "Tools & settings",
            Self::Guide => "How it works",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Files,
    Text,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Classic,
    Pq,
    Passphrase,
    Ssh,
    Plugin,
    Auto,
}
impl Protection {
    const ALL: [Self; 6] = [
        Self::Pq,
        Self::Classic,
        Self::Passphrase,
        Self::Ssh,
        Self::Plugin,
        Self::Auto,
    ];
    fn code(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Pq => "pq",
            Self::Passphrase => "passphrase",
            Self::Ssh => "ssh",
            Self::Plugin => "plugin",
            Self::Auto => "auto",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Classic => "Classic · X25519",
            Self::Pq => "Post-quantum · ML-KEM + X25519",
            Self::Passphrase => "Passphrase · scrypt",
            Self::Ssh => "SSH · Ed25519 or RSA",
            Self::Plugin => "Plugin / hardware key",
            Self::Auto => "Detect from recipient keys",
        }
    }
    fn help(self) -> &'static str {
        match self {
            Self::Classic => {
                "Use compact age1 public keys. Compatible with older age applications."
            }
            Self::Pq => {
                "Hybrid ML-KEM-768 + X25519 protects against future quantum attacks. Requires age1pq1 keys and age 1.3+."
            }
            Self::Passphrase => {
                "Anyone with the passphrase can decrypt. Share it separately from the encrypted file."
            }
            Self::Ssh => {
                "Use an existing ssh-ed25519 or ssh-rsa public key. The matching private key unlocks the file; ssh-agent is not supported."
            }
            Self::Plugin => {
                "Use a plugin recipient, identity file, or plugin name. PINs, confirmations, and touch requests appear here."
            }
            Self::Auto => {
                "Keys determine the protection. Multiple recipients can each decrypt; age rejects incompatible combinations."
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Pq,
    Classic,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretTarget {
    File,
    Key,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    Inputs,
    Recipients,
    Identities,
    KeyOpen,
    Inspect,
    OutputDir,
    OutputFile,
    KeySave,
    PublicSave,
    TextSave,
    InspectSave,
    PluginDir,
}
#[derive(Clone)]
pub enum Purpose {
    Text,
    GeneratedKey(PathBuf),
    PublicKeys(Vec<PathBuf>),
    Inspect,
    Password(SecretTarget),
    Version,
}
#[derive(Clone)]
struct SelectedFile {
    path: PathBuf,
    size: u64,
}

#[derive(Clone)]
pub enum Message {
    Navigate(Page),
    InputMode(InputMode),
    Protection(Protection),
    KeyKind(KeyKind),
    Pick(Pick),
    Picked(Pick, Vec<PathBuf>),
    Remove(Pick, usize),
    ClearFiles,
    Recipients(shad::textarea::Action),
    TextEdit(shad::textarea::Action),
    Password(SecretTarget, Zeroizing<String>),
    Confirm(SecretTarget, Zeroizing<String>),
    Reveal(SecretTarget),
    GeneratePassword(SecretTarget),
    ProtectKey(bool),
    PluginNames(String),
    PasteIdentity,
    IdentityPasted(Option<String>),
    ClearIdentity,
    PasteText,
    TextPasted(Option<String>),
    Armor(bool),
    Overwrite(bool),
    ResetOutput,
    Start,
    StartConfirmed,
    ConfirmReplace(bool),
    Cancel,
    Tick,
    Finished(Vec<FileResult>),
    EngineDone(Purpose, Result<Response, String>),
    PromptReply(bool),
    PromptValue(Zeroizing<String>),
    CopyPublic,
    UsePublic,
    CopyText,
    UseTextOutput,
    CopyInspection,
    CopyCommand,
    InspectInput,
    TextSaved(Result<(), String>),
    CheckEngine,
    ToggleTheme,
    Renderer(String),
    Restart,
    Dismiss,
    Window(window::Id, window::Event),
    Close(window::Id),
    Stay,
    FirstFrame,
    System(iced::system::Information),
    Captured(window::Screenshot),
    ProbeExit,
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UI event (data redacted)")
    }
}

pub struct App {
    page: Page,
    operation: Operation,
    input_mode: InputMode,
    protection: Protection,
    files: Vec<SelectedFile>,
    recipients: shad::textarea::Content,
    recipient_files: Vec<PathBuf>,
    identities: Vec<PathBuf>,
    identity_text: Zeroizing<String>,
    text_input: shad::textarea::Content,
    text_output: Zeroizing<String>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    reveal: bool,
    key_password: Zeroizing<String>,
    key_confirmation: Zeroizing<String>,
    key_reveal: bool,
    key_kind: KeyKind,
    protect_key: bool,
    key_paths: Vec<PathBuf>,
    public_keys: Vec<String>,
    plugin_names: String,
    plugin_dir: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    output_file: Option<PathBuf>,
    armor: bool,
    overwrite: bool,
    confirm_replace: bool,
    inspect_path: Option<PathBuf>,
    inspection: Option<serde_json::Value>,
    engine_info: String,
    graphics_info: String,
    next_renderer: String,
    dark: bool,
    picker_open: bool,
    progress: Option<Arc<Progress>>,
    prompt: Option<Prompt>,
    prompt_value: Zeroizing<String>,
    task_title: String,
    status: String,
    results: Vec<FileResult>,
    notice: Option<(bool, String)>,
    close_requested: Option<window::Id>,
    hovered: bool,
    options: Options,
    first_frame: Option<f64>,
}
impl App {
    pub fn boot(options: Options) -> (Self, Task<Message>) {
        let initial = options.files.clone();
        let page = match options.page.as_str() {
            "decrypt" => Page::Decrypt,
            "keys" => Page::Keys,
            "inspect" => Page::Inspect,
            "settings" => Page::Settings,
            "guide" => Page::Guide,
            _ => Page::Encrypt,
        };
        let renderer = options.renderer.clone();
        let dark = options.dark;
        let app = Self {
            page,
            operation: if page == Page::Decrypt {
                Operation::Decrypt
            } else {
                Operation::Encrypt
            },
            input_mode: InputMode::Files,
            protection: Protection::Pq,
            files: vec![],
            recipients: shad::textarea::Content::new(),
            recipient_files: vec![],
            identities: vec![],
            identity_text: Zeroizing::new(String::new()),
            text_input: shad::textarea::Content::new(),
            text_output: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            confirmation: Zeroizing::new(String::new()),
            reveal: false,
            key_password: Zeroizing::new(String::new()),
            key_confirmation: Zeroizing::new(String::new()),
            key_reveal: false,
            key_kind: KeyKind::Pq,
            protect_key: false,
            key_paths: vec![],
            public_keys: vec![],
            plugin_names: String::new(),
            plugin_dir: None,
            output_dir: None,
            output_file: None,
            armor: false,
            overwrite: false,
            confirm_replace: false,
            inspect_path: None,
            inspection: None,
            engine_info: "Official age 1.3.2 · loaded only when needed".into(),
            graphics_info: String::new(),
            next_renderer: renderer,
            dark,
            picker_open: false,
            progress: None,
            prompt: None,
            prompt_value: Zeroizing::new(String::new()),
            task_title: String::new(),
            status: String::new(),
            results: vec![],
            notice: None,
            close_requested: None,
            hovered: false,
            options,
            first_frame: None,
        };
        (
            app,
            if initial.is_empty() {
                Task::none()
            } else {
                Task::done(Message::Picked(
                    if page == Page::Inspect {
                        Pick::Inspect
                    } else if page == Page::Keys {
                        Pick::KeyOpen
                    } else {
                        Pick::Inputs
                    },
                    initial,
                ))
            },
        )
    }
    pub fn theme(&self) -> Theme {
        shad::theme::zinc(if self.dark { Mode::Dark } else { Mode::Light }).build()
    }
    fn busy(&self) -> bool {
        self.progress.is_some()
    }
    fn blocked(&self) -> bool {
        self.busy() || self.picker_open || self.confirm_replace
    }
    fn size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
    fn working(&self) -> bool {
        matches!(self.page, Page::Encrypt | Page::Decrypt)
    }
    fn clear_passwords(&mut self) {
        self.password.zeroize();
        self.confirmation.zeroize();
        self.key_password.zeroize();
        self.key_confirmation.zeroize();
        self.prompt_value.zeroize();
        self.reveal = false;
        self.key_reveal = false;
    }
    fn notice(&mut self, error: bool, message: impl Into<String>) {
        self.notice = Some((error, message.into()));
    }
    fn progress(&mut self, title: &str) -> Arc<Progress> {
        let p = Arc::new(Progress::default());
        self.progress = Some(p.clone());
        self.task_title = title.into();
        self.status = String::new();
        self.notice = None;
        p
    }
    fn finish(&mut self) {
        self.progress = None;
        self.prompt = None;
        self.prompt_value.zeroize();
        self.status.clear();
    }
    fn request(&self, operation: &str) -> Result<Request, String> {
        let mut r = Request::new(operation);
        r.protection = self.protection.code().into();
        r.armor = self.armor;
        r.plugin_dir = self
            .plugin_dir
            .as_ref()
            .map(|p| crypto::path_string(p))
            .transpose()?
            .unwrap_or_default();
        if operation == "encrypt" && self.protection == Protection::Passphrase {
            r.passphrase = self.password.to_string();
            return Ok(r);
        }
        r.recipients = self.recipients.text();
        r.recipient_files = self
            .recipient_files
            .iter()
            .map(|p| crypto::path_string(p))
            .collect::<Result<_, _>>()?;
        r.identity_files = self
            .identities
            .iter()
            .map(|p| crypto::path_string(p))
            .collect::<Result<_, _>>()?;
        r.identity_text = self.identity_text.to_string();
        r.plugins = self
            .plugin_names
            .split([',', ' ', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if operation == "decrypt" {
            r.recipients.clear();
            r.recipient_files.clear();
            r.passphrase = self.password.to_string();
            r.protection = "auto".into();
        }
        Ok(r)
    }
    fn launch_engine(&mut self, purpose: Purpose, request: Request, title: &str) -> Task<Message> {
        let p = self.progress(title);
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || engine::run(&request, p))
                    .await
                    .unwrap_or_else(|_| Err("Engine worker stopped unexpectedly.".into()))
            },
            move |result| Message::EngineDone(purpose.clone(), result),
        )
    }
    pub fn subscription(&self) -> Subscription<Message> {
        let mut s = vec![
            window::events().map(|(id, event)| Message::Window(id, event)),
            iced::event::listen_with(|event, status, _| {
                if status == iced::event::Status::Captured {
                    return None;
                }
                if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key,
                    modifiers,
                    ..
                }) = event
                {
                    shortcut(&key, modifiers)
                } else {
                    None
                }
            }),
        ];
        if self.first_frame.is_none() {
            s.push(window::frames().map(|_| Message::FirstFrame));
        }
        if self.busy() {
            s.push(iced::time::every(Duration::from_millis(100)).map(|_| Message::Tick));
        }
        Subscription::batch(s)
    }
    pub fn update(&mut self, message: Message) -> Task<Message> {
        let previous_page = self.page;
        let previous_mode = self.input_mode;
        let show_result = matches!(
            &message,
            Message::Finished(_)
                | Message::EngineDone(
                    Purpose::Text
                        | Purpose::GeneratedKey(_)
                        | Purpose::PublicKeys(_)
                        | Purpose::Inspect,
                    _
                )
                | Message::EngineDone(_, Err(_))
        );
        match message {
            Message::Navigate(page) if !self.blocked() => {
                if matches!(page, Page::Encrypt | Page::Decrypt) {
                    let operation = if page == Page::Encrypt {
                        Operation::Encrypt
                    } else {
                        Operation::Decrypt
                    };
                    if operation != self.operation {
                        self.files.clear();
                        self.text_input = shad::textarea::Content::new();
                        self.text_output.zeroize();
                        self.output_file = None;
                    }
                    self.operation = operation;
                }
                self.page = page;
                self.notice = None;
                self.clear_passwords();
                self.results.clear();
                if page == Page::Settings {
                    return Task::batch([
                        iced::system::information().map(Message::System),
                        iced::widget::operation::snap_to(
                            "workspace-scroll",
                            iced::widget::operation::RelativeOffset::START,
                        ),
                    ]);
                }
            }
            Message::InputMode(mode) if !self.blocked() => {
                self.input_mode = mode;
                self.notice = None;
                self.results.clear();
            }
            Message::Protection(p) if !self.blocked() => {
                self.protection = p;
                self.password.zeroize();
                self.confirmation.zeroize();
                self.notice = None;
            }
            Message::KeyKind(k) if !self.blocked() => self.key_kind = k,
            Message::Pick(pick) if !self.blocked() => {
                if pick == Pick::KeySave
                    && self.protect_key
                    && let Err(e) = password_valid(&self.key_password, &self.key_confirmation)
                {
                    self.notice(true, e);
                    return Task::none();
                }
                if pick == Pick::OutputFile && self.files.len() != 1 {
                    self.notice(true, "Choose one input file to use Save as.");
                    return Task::none();
                }
                self.picker_open = true;
                let default_name = match pick {
                    Pick::KeySave => {
                        if self.protect_key {
                            "identity.age"
                        } else {
                            "identity.agekey"
                        }
                    }
                    Pick::PublicSave => "recipients.txt",
                    Pick::TextSave => {
                        if self.operation == Operation::Encrypt {
                            "message.age.txt"
                        } else {
                            "message.txt"
                        }
                    }
                    Pick::InspectSave => "age-inspection.json",
                    _ => "output.age",
                }
                .to_owned();
                let output_name = if pick == Pick::OutputFile {
                    self.files
                        .first()
                        .and_then(|f| {
                            crypto::output_path(&f.path, None, self.operation, self.armor).ok()
                        })
                        .map(|p| filename(&p))
                        .unwrap_or(default_name)
                } else {
                    default_name
                };
                return Task::perform(
                    async move {
                        let dialog = rfd::AsyncFileDialog::new();
                        match pick {
                            Pick::OutputDir | Pick::PluginDir => dialog
                                .set_title(if pick == Pick::PluginDir {
                                    "Choose the folder containing age plugins"
                                } else {
                                    "Choose output folder"
                                })
                                .pick_folder()
                                .await
                                .map(|f| vec![f.path().to_owned()])
                                .unwrap_or_default(),
                            Pick::KeySave
                            | Pick::PublicSave
                            | Pick::TextSave
                            | Pick::InspectSave
                            | Pick::OutputFile => dialog
                                .set_title(if pick == Pick::KeySave {
                                    "Save your secret identity"
                                } else {
                                    "Save a new file"
                                })
                                .set_file_name(output_name)
                                .save_file()
                                .await
                                .map(|f| vec![f.path().to_owned()])
                                .unwrap_or_default(),
                            Pick::Inspect => dialog
                                .set_title("Choose an encrypted age file")
                                .pick_file()
                                .await
                                .map(|f| vec![f.path().to_owned()])
                                .unwrap_or_default(),
                            _ => dialog
                                .set_title(match pick {
                                    Pick::Recipients => "Choose recipient / SSH public-key files",
                                    Pick::Identities | Pick::KeyOpen => {
                                        "Choose age or SSH identity files"
                                    }
                                    _ => "Choose input files",
                                })
                                .pick_files()
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .map(|f| f.path().to_owned())
                                .collect(),
                        }
                    },
                    move |paths| Message::Picked(pick, paths),
                );
            }
            Message::Picked(pick, paths) => {
                self.picker_open = false;
                if paths.is_empty() || self.busy() {
                    return Task::none();
                }
                match pick {
                    Pick::Inputs => {
                        for path in paths {
                            if self.files.iter().any(|f| f.path == path) {
                                continue;
                            }
                            match crypto::file_size(&path) {
                                Ok(size) => self.files.push(SelectedFile { path, size }),
                                Err(e) => self.notice(true, e),
                            }
                        }
                        self.results.clear();
                        if self.files.len() > 1 {
                            self.output_file = None;
                        }
                    }
                    Pick::Recipients => append_unique(&mut self.recipient_files, paths),
                    Pick::Identities => append_unique(&mut self.identities, paths),
                    Pick::PluginDir => self.plugin_dir = paths.first().cloned(),
                    Pick::OutputDir => {
                        self.output_dir = paths.first().cloned();
                        self.output_file = None;
                    }
                    Pick::OutputFile => self.output_file = paths.first().cloned(),
                    Pick::KeySave => {
                        let path = paths[0].clone();
                        let mut r = Request::new("generate_key");
                        r.key_kind = if self.key_kind == KeyKind::Pq {
                            "pq"
                        } else {
                            "classic"
                        }
                        .into();
                        r.protect_key = self.protect_key;
                        r.passphrase = std::mem::take(&mut *self.key_password);
                        self.key_confirmation.zeroize();
                        let p = self.progress("Creating your identity");
                        let target = path.clone();
                        return Task::perform(
                            async move {
                                tokio::task::spawn_blocking(move || {
                                    crypto::generate_identity(&target, r, p)
                                })
                                .await
                                .unwrap_or_else(|_| Err("Key worker stopped.".into()))
                            },
                            move |result| {
                                Message::EngineDone(Purpose::GeneratedKey(path.clone()), result)
                            },
                        );
                    }
                    Pick::KeyOpen => {
                        let mut r = Request::new("public_keys");
                        r.identity_files = paths
                            .iter()
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect();
                        r.plugin_dir = self
                            .plugin_dir
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        return self.launch_engine(
                            Purpose::PublicKeys(paths),
                            r,
                            "Opening your identities",
                        );
                    }
                    Pick::Inspect => {
                        self.inspect_path = Some(paths[0].clone());
                        let mut r = Request::new("inspect");
                        r.input = paths[0].to_string_lossy().into_owned();
                        return self.launch_engine(
                            Purpose::Inspect,
                            r,
                            "Inspecting the encrypted file",
                        );
                    }
                    Pick::PublicSave | Pick::TextSave | Pick::InspectSave => {
                        let content = match pick {
                            Pick::PublicSave => format!("{}\n", self.public_keys.join("\n")),
                            Pick::InspectSave => {
                                serde_json::to_string_pretty(&self.inspection).unwrap_or_default()
                            }
                            _ => self.text_output.to_string(),
                        };
                        let private =
                            pick == Pick::TextSave && self.operation == Operation::Decrypt;
                        let path = paths[0].clone();
                        return Task::perform(
                            async move {
                                tokio::task::spawn_blocking(move || {
                                    crypto::save_text(&path, &content, private)
                                })
                                .await
                                .unwrap_or_else(|_| Err("Save worker stopped.".into()))
                            },
                            Message::TextSaved,
                        );
                    }
                }
            }
            Message::Remove(kind, i) if !self.blocked() => {
                match kind {
                    Pick::Inputs => {
                        if i < self.files.len() {
                            self.files.remove(i);
                        }
                    }
                    Pick::Recipients => {
                        if i < self.recipient_files.len() {
                            self.recipient_files.remove(i);
                        }
                    }
                    Pick::Identities => {
                        if i < self.identities.len() {
                            self.identities.remove(i);
                        }
                    }
                    _ => {}
                }
                self.results.clear();
            }
            Message::ClearFiles if !self.blocked() => {
                self.files.clear();
                self.results.clear();
                self.output_file = None;
            }
            Message::Recipients(action) if !self.blocked() => self.recipients.perform(action),
            Message::TextEdit(action) if !self.blocked() => self.text_input.perform(action),
            Message::Password(target, value) if !self.blocked() => match target {
                SecretTarget::Key => self.key_password = value,
                _ => self.password = value,
            },
            Message::Confirm(target, value) if !self.blocked() => match target {
                SecretTarget::Key => self.key_confirmation = value,
                _ => self.confirmation = value,
            },
            Message::Reveal(target) => match target {
                SecretTarget::Key => self.key_reveal = !self.key_reveal,
                _ => self.reveal = !self.reveal,
            },
            Message::GeneratePassword(target) if !self.blocked() => {
                return self.launch_engine(
                    Purpose::Password(target),
                    Request::new("generate_passphrase"),
                    "Generating a secure passphrase",
                );
            }
            Message::ProtectKey(value) if !self.blocked() => self.protect_key = value,
            Message::PluginNames(value) if !self.blocked() => self.plugin_names = value,
            Message::PasteIdentity if !self.blocked() => {
                return iced::clipboard::read().map(Message::IdentityPasted);
            }
            Message::IdentityPasted(Some(value)) => {
                if value.len() > 16 * 1024 * 1024 {
                    self.notice(true, "Pasted identity exceeds 16 MiB.");
                } else {
                    self.identity_text = Zeroizing::new(value);
                    self.notice(
                        false,
                        "Pasted identity loaded for this session. Its secret is hidden.",
                    );
                }
            }
            Message::ClearIdentity if !self.blocked() => self.identity_text.zeroize(),
            Message::PasteText if !self.blocked() => {
                return iced::clipboard::read().map(Message::TextPasted);
            }
            Message::TextPasted(Some(value)) => {
                if value.len() > 2 * 1024 * 1024 {
                    self.notice(true, "Use Files for text larger than 2 MiB.");
                } else {
                    self.text_input = shad::textarea::Content::with_text(&value);
                }
            }
            Message::Armor(value) if !self.blocked() => self.armor = value,
            Message::Overwrite(value) if !self.blocked() => self.overwrite = value,
            Message::ResetOutput if !self.blocked() => {
                self.output_dir = None;
                self.output_file = None;
            }
            Message::Start if !self.blocked() && self.working() => {
                if let Err(e) = self.validate() {
                    self.notice(true, e);
                    return Task::none();
                }
                if self.overwrite && self.input_mode == InputMode::Files {
                    self.confirm_replace = true;
                } else {
                    return self.start();
                }
            }
            Message::StartConfirmed => {
                self.confirm_replace = false;
                if !self.busy() {
                    return self.start();
                }
            }
            Message::ConfirmReplace(false) => self.confirm_replace = false,
            Message::ConfirmReplace(true) => return Task::done(Message::StartConfirmed),
            Message::Cancel => {
                if let Some(p) = &self.progress {
                    p.cancel();
                }
                self.prompt = None;
                self.prompt_value.zeroize();
            }
            Message::Tick => {
                if let Some(p) = &self.progress {
                    let prompt = p.prompt.lock().unwrap().clone();
                    if self.prompt.as_ref().map(|p| p.id) != prompt.as_ref().map(|p| p.id) {
                        self.prompt_value.zeroize();
                    }
                    self.prompt = prompt;
                    self.status = p.status.lock().unwrap().clone();
                }
            }
            Message::PromptValue(value) => self.prompt_value = value,
            Message::PromptReply(yes) => {
                if let (Some(prompt), Some(p)) = (&self.prompt, &self.progress) {
                    let value = if !prompt.yes.is_empty() {
                        if yes { "yes" } else { "no" }.into()
                    } else {
                        std::mem::take(&mut *self.prompt_value)
                    };
                    p.respond(prompt.id, value, false);
                }
                self.prompt = None;
                self.prompt_value.zeroize();
            }
            Message::Finished(results) => {
                self.finish();
                self.results = results;
                let successes = self.results.iter().filter(|r| r.output.is_some()).count();
                self.notice(
                    successes != self.results.len(),
                    format!(
                        "{} of {} files {}. Originals are unchanged.",
                        successes,
                        self.results.len(),
                        if self.operation == Operation::Encrypt {
                            "encrypted"
                        } else {
                            "decrypted"
                        }
                    ),
                );
                if let Some(id) = self.close_requested.take() {
                    return window::close(id);
                }
            }
            Message::EngineDone(purpose, result) => {
                self.finish();
                match result {
                    Err(e) => self.notice(true, e),
                    Ok(mut response) => match purpose {
                        Purpose::Text => {
                            self.text_output =
                                Zeroizing::new(response.text.take().unwrap_or_default());
                            self.notice(false, "Done. Copy the result or save it as a file.");
                        }
                        Purpose::GeneratedKey(path) => {
                            self.key_paths = vec![path];
                            self.public_keys = std::mem::take(&mut response.public_keys);
                            self.notice(false,"Identity saved. Back it up; share only the public recipient below.");
                        }
                        Purpose::PublicKeys(paths) => {
                            self.key_paths = paths;
                            self.public_keys = std::mem::take(&mut response.public_keys);
                            self.notice(false,"Public recipients extracted. Secret identities stay in their files.");
                        }
                        Purpose::Inspect => self.inspection = response.metadata.take(),
                        Purpose::Password(target) => {
                            let value = response.text.take().unwrap_or_default();
                            match target {
                                SecretTarget::Key => {
                                    self.key_confirmation = Zeroizing::new(value.clone());
                                    self.key_password = Zeroizing::new(value);
                                    self.key_reveal = true;
                                }
                                _ => {
                                    self.confirmation = Zeroizing::new(value.clone());
                                    self.password = Zeroizing::new(value);
                                    self.reveal = true;
                                }
                            }
                            self.notice(false,"Generated a 192-bit random passphrase. Keep a copy before encrypting.");
                        }
                        Purpose::Version => {
                            self.engine_info = format!("{} · {}", response.engine, response.go)
                        }
                    },
                }
                if let Some(id) = self.close_requested.take() {
                    return window::close(id);
                }
            }
            Message::CopyPublic => return iced::clipboard::write(self.public_keys.join("\n")),
            Message::UsePublic if !self.blocked() => {
                self.page = Page::Encrypt;
                self.operation = Operation::Encrypt;
                self.recipients = shad::textarea::Content::with_text(&self.public_keys.join("\n"));
                self.protection = Protection::Auto;
                self.recipient_files.clear();
                self.notice = None;
            }
            Message::CopyText => return iced::clipboard::write(self.text_output.to_string()),
            Message::UseTextOutput if !self.blocked() => {
                self.text_input = shad::textarea::Content::with_text(&self.text_output);
                self.text_output.zeroize();
                self.operation = if self.operation == Operation::Encrypt {
                    Operation::Decrypt
                } else {
                    Operation::Encrypt
                };
                self.page = if self.operation == Operation::Encrypt {
                    Page::Encrypt
                } else {
                    Page::Decrypt
                };
                self.input_mode = InputMode::Text;
                self.notice = None;
            }
            Message::CopyInspection => {
                return iced::clipboard::write(
                    serde_json::to_string_pretty(&self.inspection).unwrap_or_default(),
                );
            }
            Message::CopyCommand => return iced::clipboard::write(self.cli_preview()),
            Message::InspectInput if !self.blocked() => {
                let mut r = Request::new("inspect");
                if self.input_mode == InputMode::Text {
                    r.text = Some(self.text_input.text());
                } else if let Some(file) = self.files.first() {
                    r.input = file.path.to_string_lossy().into_owned();
                    self.inspect_path = Some(file.path.clone());
                } else {
                    self.notice(true, "Choose an encrypted file first.");
                    return Task::none();
                }
                self.page = Page::Inspect;
                return self.launch_engine(Purpose::Inspect, r, "Inspecting the encrypted input");
            }
            Message::TextSaved(result) => match result {
                Ok(()) => self.notice(false, "Saved as a new file."),
                Err(e) => self.notice(true, e),
            },
            Message::CheckEngine if !self.blocked() => {
                return self.launch_engine(
                    Purpose::Version,
                    Request::new("version"),
                    "Checking the official engine",
                );
            }
            Message::ToggleTheme => self.dark = !self.dark,
            Message::Renderer(value) if !self.blocked() => self.next_renderer = value,
            Message::Restart if !self.blocked() => {
                if let Ok(path) = std::env::current_exe() {
                    let mut command = std::process::Command::new(path);
                    command.arg("--renderer").arg(&self.next_renderer);
                    if self.dark {
                        command.arg("--dark");
                    }
                    match command.spawn() {
                        Ok(_) => return window::oldest().and_then(window::close),
                        Err(e) => self.notice(true, format!("Cannot restart: {e}")),
                    }
                }
            }
            Message::Dismiss => self.notice = None,
            Message::Window(_, window::Event::FileDropped(path)) => {
                self.hovered = false;
                if !self.blocked() {
                    let pick = if self.page == Page::Inspect {
                        Pick::Inspect
                    } else if self.page == Page::Keys {
                        Pick::KeyOpen
                    } else {
                        Pick::Inputs
                    };
                    return Task::done(Message::Picked(pick, vec![path]));
                }
            }
            Message::Window(_, window::Event::FileHovered(_)) => self.hovered = true,
            Message::Window(_, window::Event::FilesHoveredLeft) => self.hovered = false,
            Message::Window(id, window::Event::CloseRequested) => {
                if self.busy() {
                    self.close_requested = Some(id);
                } else {
                    self.clear_passwords();
                    return window::close(id);
                }
            }
            Message::Close(id) => {
                self.close_requested = Some(id);
                if let Some(p) = &self.progress {
                    p.cancel();
                } else {
                    return window::close(id);
                }
            }
            Message::Stay => self.close_requested = None,
            Message::FirstFrame if self.first_frame.is_none() => {
                self.first_frame = Some(self.options.started.elapsed().as_secs_f64() * 1000.0);
                if let Some(dir) = &self.options.probe {
                    let _ = std::fs::create_dir_all(dir);
                    let _ = std::fs::write(
                        dir.join("first-frame-ms.txt"),
                        format!("{:.3}", self.first_frame.unwrap()),
                    );
                    return Task::batch([
                        iced::system::information().map(Message::System),
                        window::oldest()
                            .and_then(window::screenshot)
                            .map(Message::Captured),
                        Task::perform(
                            async { tokio::time::sleep(Duration::from_secs(3)).await },
                            |_| Message::ProbeExit,
                        ),
                    ]);
                }
            }
            Message::System(info) => {
                self.graphics_info =
                    format!("{} · {}", info.graphics_backend, info.graphics_adapter);
                if let Some(dir) = &self.options.probe {
                    let _ = std::fs::write(
                        dir.join("renderer.txt"),
                        format!(
                            "backend={}\nadapter={}\nmemory_bytes={:?}\n",
                            info.graphics_backend, info.graphics_adapter, info.memory_used
                        ),
                    );
                }
            }
            Message::Captured(s) => {
                if let Some(dir) = &self.options.probe {
                    let _ = image::save_buffer(
                        dir.join("window.png"),
                        &s.rgba,
                        s.size.width,
                        s.size.height,
                        image::ColorType::Rgba8,
                    );
                    let _ = std::fs::write(
                        dir.join("capture-ms.txt"),
                        format!(
                            "{:.3}",
                            self.options.started.elapsed().as_secs_f64() * 1000.0
                        ),
                    );
                }
            }
            Message::ProbeExit => return window::oldest().and_then(window::close),
            _ => {}
        }
        if previous_page != self.page || previous_mode != self.input_mode {
            return iced::widget::operation::snap_to(
                "workspace-scroll",
                iced::widget::operation::RelativeOffset::START,
            );
        }
        if show_result {
            return iced::widget::operation::snap_to_end("workspace-scroll");
        }
        Task::none()
    }
    fn validate(&self) -> Result<(), String> {
        if self.input_mode == InputMode::Files && self.files.is_empty() {
            return Err("Choose at least one input file.".into());
        }
        let text = self.text_input.text();
        let limit = if self.operation == Operation::Encrypt {
            1024 * 1024
        } else {
            2 * 1024 * 1024
        };
        if self.input_mode == InputMode::Text && (text.is_empty() || text.len() > limit) {
            return Err(format!(
                "Enter text up to {} MiB, or use Files for larger input.",
                limit / (1024 * 1024)
            ));
        }
        if self.operation == Operation::Encrypt {
            if self.protection == Protection::Passphrase {
                password_valid(&self.password, &self.confirmation)?;
            } else if self.recipients.text().trim().is_empty()
                && self.recipient_files.is_empty()
                && self.identities.is_empty()
                && self.identity_text.is_empty()
                && self.plugin_names.trim().is_empty()
            {
                return Err("Add a recipient key, recipient file, identity, or plugin.".into());
            }
        }
        Ok(())
    }
    fn start(&mut self) -> Task<Message> {
        if let Err(e) = self.validate() {
            self.notice(true, e);
            return Task::none();
        }
        let mut r = match self.request(self.operation.name()) {
            Ok(r) => r,
            Err(e) => {
                self.notice(true, e);
                return Task::none();
            }
        };
        self.password.zeroize();
        self.confirmation.zeroize();
        self.reveal = false;
        self.results.clear();
        if self.input_mode == InputMode::Text {
            r.text = Some(self.text_input.text());
            return self.launch_engine(Purpose::Text, r, "Processing your text");
        }
        let job = Job {
            operation: self.operation,
            inputs: self.files.iter().map(|f| f.path.clone()).collect(),
            output_dir: self.output_dir.clone(),
            output_file: self.output_file.clone(),
            overwrite: self.overwrite,
            request: r,
        };
        let p = self.progress(if self.operation == Operation::Encrypt {
            "Encrypting your files"
        } else {
            "Decrypting your files"
        });
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || crypto::run(job, p))
                    .await
                    .unwrap_or_else(|_| {
                        vec![FileResult {
                            input: PathBuf::from("Operation"),
                            output: None,
                            error: Some("File worker stopped unexpectedly.".into()),
                        }]
                    })
            },
            Message::Finished,
        )
    }
    fn cli_preview(&self) -> String {
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let mut args = vec![
            "age".to_owned(),
            if self.operation == Operation::Encrypt {
                "--encrypt"
            } else {
                "--decrypt"
            }
            .into(),
        ];
        if self.operation == Operation::Encrypt && self.protection == Protection::Passphrase {
            args.push("--passphrase".into());
        } else {
            if self.operation == Operation::Encrypt {
                for rec in self
                    .recipients
                    .text()
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                {
                    args.extend(["--recipient".into(), quote(rec)]);
                }
                for p in &self.recipient_files {
                    args.extend(["--recipients-file".into(), quote(&p.display().to_string())]);
                }
            }
            for p in &self.identities {
                args.extend(["--identity".into(), quote(&p.display().to_string())]);
            }
            for name in self
                .plugin_names
                .split([',', ' ', '\n'])
                .filter(|s| !s.is_empty())
            {
                args.extend(["-j".into(), quote(name)]);
            }
            if !self.identity_text.is_empty() {
                args.extend(["--identity".into(), "<pasted-identity-file>".into()]);
            }
        }
        if self.operation == Operation::Encrypt
            && (self.armor || self.input_mode == InputMode::Text)
        {
            args.push("--armor".into());
        }
        if let Some(file) = self
            .files
            .first()
            .filter(|_| self.input_mode == InputMode::Files)
        {
            if let Some(output) = self.output_file.clone().or_else(|| {
                crypto::output_path(
                    &file.path,
                    self.output_dir.as_deref(),
                    self.operation,
                    self.armor,
                )
                .ok()
            }) {
                args.extend(["--output".into(), quote(&output.display().to_string())]);
            }
            args.push(quote(&file.path.display().to_string()));
        } else {
            args.push(
                if self.operation == Operation::Encrypt {
                    "'<plaintext-file>'"
                } else {
                    "'<armored-file>'"
                }
                .into(),
            );
        }
        args.join(" ")
    }
}
fn password_valid(value: &str, confirm: &str) -> Result<(), String> {
    if value.chars().count() < 12 {
        return Err("Use at least 12 characters, or generate a secure passphrase.".into());
    }
    if value != confirm {
        return Err("The two passphrases do not match.".into());
    }
    Ok(())
}
fn append_unique(target: &mut Vec<PathBuf>, paths: Vec<PathBuf>) {
    for p in paths {
        if !target.contains(&p) {
            target.push(p);
        }
    }
}
fn filename(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}
fn shortcut(key: &iced::keyboard::Key, modifiers: iced::keyboard::Modifiers) -> Option<Message> {
    if !modifiers.command() {
        return None;
    }
    match key.as_ref() {
        iced::keyboard::Key::Character("o") => Some(Message::Pick(Pick::Inputs)),
        iced::keyboard::Key::Character("1") => Some(Message::Navigate(Page::Encrypt)),
        iced::keyboard::Key::Character("2") => Some(Message::Navigate(Page::Decrypt)),
        iced::keyboard::Key::Character("3") => Some(Message::Navigate(Page::Keys)),
        iced::keyboard::Key::Named(iced::keyboard::key::Named::Enter) => Some(Message::Start),
        _ => None,
    }
}
