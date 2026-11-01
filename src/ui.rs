use crate::Options;
use age::secrecy::SecretString;
use age_desktop::crypto::{self, Credential, FileResult, Job, Operation, Progress};
use iced::widget::{self, column, container, row, scrollable, space, text};
use iced::{
    Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme, window,
};
use shadcn_iced::prelude::*;
use shadcn_iced::{self as shad, font, tokens};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Encrypt,
    Decrypt,
    Keys,
    Guide,
}
impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt files",
            Self::Decrypt => "Decrypt files",
            Self::Keys => "Your keys",
            Self::Guide => "A little peace of mind.",
        }
    }
    fn operation(self) -> Operation {
        if self == Self::Decrypt {
            Operation::Decrypt
        } else {
            Operation::Encrypt
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Key,
    Passphrase,
}

#[derive(Clone)]
struct SelectedFile {
    path: PathBuf,
    size: u64,
}

#[derive(Clone)]
pub enum Message {
    Navigate(Page),
    Method(Method),
    PickFiles,
    FilesPicked(Vec<PathBuf>),
    RemoveFile(usize),
    ClearFiles,
    Recipients(shad::textarea::Action),
    Password(Zeroizing<String>),
    Confirm(Zeroizing<String>),
    Reveal,
    PickIdentity,
    IdentityPicked(Option<PathBuf>),
    IdentityReady(PathBuf, Result<Vec<String>, String>),
    GenerateKey,
    KeyGenerated(Option<(PathBuf, Result<String, String>)>),
    CopyPublic,
    UsePublic,
    PickOutput,
    OutputPicked(Option<PathBuf>),
    ResetOutput,
    Armor(bool),
    Start,
    Cancel,
    Finished(Vec<FileResult>),
    Tick,
    ToggleTheme,
    Dismiss,
    Window(window::Id, window::Event),
    FirstFrame,
    System(iced::system::Information),
    Captured(window::Screenshot),
    ProbeExit,
    Close(window::Id),
    Stay,
}

// Input events can contain secrets. Do not let debug tools format their data.
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UI event (data redacted)")
    }
}

pub struct App {
    page: Page,
    method: Method,
    files: Vec<SelectedFile>,
    recipients: shad::textarea::Content,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    reveal: bool,
    identity: Option<PathBuf>,
    public_keys: Vec<String>,
    output: Option<PathBuf>,
    armor: bool,
    dark: bool,
    progress: Option<Arc<Progress>>,
    results: Vec<FileResult>,
    notice: Option<(bool, String)>,
    started_job: Option<Instant>,
    close_requested: Option<window::Id>,
    picker_open: bool,
    options: Options,
    first_frame: Option<f64>,
    hovered: bool,
}

impl App {
    pub fn boot(options: Options) -> (Self, Task<Message>) {
        let initial = options.files.clone();
        let app = Self {
            page: Page::Encrypt,
            method: Method::Key,
            files: Vec::new(),
            recipients: shad::textarea::Content::new(),
            password: Zeroizing::new(String::new()),
            confirmation: Zeroizing::new(String::new()),
            reveal: false,
            identity: None,
            public_keys: Vec::new(),
            output: None,
            armor: false,
            dark: options.dark,
            progress: None,
            results: Vec::new(),
            notice: None,
            started_job: None,
            close_requested: None,
            picker_open: false,
            options,
            first_frame: None,
            hovered: false,
        };
        (
            app,
            if initial.is_empty() {
                Task::none()
            } else {
                Task::done(Message::FilesPicked(initial))
            },
        )
    }

    pub fn theme(&self) -> Theme {
        shad::theme::zinc(if self.dark { Mode::Dark } else { Mode::Light }).build()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions =
            vec![window::events().map(|(id, event)| Message::Window(id, event))];
        if self.first_frame.is_none() {
            subscriptions.push(window::frames().map(|_| Message::FirstFrame));
        }
        if self.busy() {
            subscriptions
                .push(iced::time::every(Duration::from_millis(100)).map(|_| Message::Tick));
        }
        subscriptions.push(iced::event::listen_with(|event, status, _id| {
            if status == iced::event::Status::Captured {
                return None;
            }
            let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, modifiers, .. }) =
                event
            else {
                return None;
            };
            shortcut(&key, modifiers)
        }));
        Subscription::batch(subscriptions)
    }

    fn busy(&self) -> bool {
        self.progress.is_some()
    }
    fn blocked(&self) -> bool {
        self.busy() || self.picker_open
    }
    fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
    fn clear_secrets(&mut self) {
        self.password.zeroize();
        self.confirmation.zeroize();
        self.reveal = false;
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(page) if !self.blocked() => {
                if self.page != page {
                    self.page = page;
                    self.files.clear();
                    self.results.clear();
                    self.notice = None;
                    self.clear_secrets();
                }
            }
            Message::Method(method) if !self.blocked() => {
                self.method = method;
                self.clear_secrets();
                self.notice = None;
            }
            Message::PickFiles
                if !self.blocked() && matches!(self.page, Page::Encrypt | Page::Decrypt) =>
            {
                self.picker_open = true;
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Choose files")
                            .pick_files()
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|f| f.path().to_owned())
                            .collect()
                    },
                    Message::FilesPicked,
                );
            }
            Message::FilesPicked(paths) => {
                self.picker_open = false;
                if self.busy() {
                    return Task::none();
                }
                if !matches!(self.page, Page::Encrypt | Page::Decrypt) {
                    return Task::none();
                }
                for path in paths {
                    if self.files.iter().any(|f| f.path == path) {
                        continue;
                    }
                    match crypto::file_size(&path) {
                        Ok(size) => self.files.push(SelectedFile { path, size }),
                        Err(error) => self.notice = Some((true, error)),
                    }
                }
                self.results.clear();
            }
            Message::RemoveFile(i) if !self.blocked() => {
                if i < self.files.len() {
                    self.files.remove(i);
                    self.results.clear();
                }
            }
            Message::ClearFiles if !self.blocked() => {
                self.files.clear();
                self.results.clear();
            }
            Message::Recipients(action) if !self.blocked() => {
                self.recipients.perform(action);
                self.notice = None;
            }
            Message::Password(value) if !self.blocked() => self.password = value,
            Message::Confirm(value) if !self.blocked() => self.confirmation = value,
            Message::Reveal => self.reveal = !self.reveal,
            Message::PickIdentity if !self.blocked() => {
                self.picker_open = true;
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Open an age identity file")
                            .pick_file()
                            .await
                            .map(|f| f.path().to_owned())
                    },
                    Message::IdentityPicked,
                );
            }
            Message::IdentityPicked(path) => {
                if let Some(path) = path {
                    return Task::perform(
                        async move {
                            let p = path.clone();
                            let result =
                                tokio::task::spawn_blocking(move || crypto::inspect_identity(&p))
                                    .await
                                    .unwrap_or_else(|_| {
                                        Err("Key reader stopped unexpectedly.".into())
                                    });
                            (path, result)
                        },
                        |(path, result)| Message::IdentityReady(path, result),
                    );
                }
                self.picker_open = false;
            }
            Message::IdentityReady(path, result) => {
                self.picker_open = false;
                match result {
                    Ok(public) => {
                        self.identity = Some(path);
                        self.public_keys = public;
                        self.notice = Some((
                            false,
                            "Identity loaded. Only the public key is shown here.".into(),
                        ));
                    }
                    Err(error) => self.notice = Some((true, error)),
                }
            }
            Message::GenerateKey if !self.blocked() => {
                self.picker_open = true;
                return Task::perform(
                    async {
                        let target = rfd::AsyncFileDialog::new()
                            .set_title("Save your secret age identity — keep this file private")
                            .set_file_name("identity.agekey")
                            .save_file()
                            .await?;
                        let path = target.path().to_owned();
                        let p = path.clone();
                        let result =
                            tokio::task::spawn_blocking(move || crypto::generate_identity(&p))
                                .await
                                .unwrap_or_else(|_| {
                                    Err("Key generation stopped unexpectedly.".into())
                                });
                        Some((path, result))
                    },
                    Message::KeyGenerated,
                );
            }
            Message::KeyGenerated(result) => {
                self.picker_open = false;
                if let Some((path, result)) = result {
                    match result {
                        Ok(key) => {
                            self.identity = Some(path);
                            self.public_keys = vec![key];
                            self.notice = Some((
                                false,
                                "Key created. Keep the secret identity file safe and backed up."
                                    .into(),
                            ));
                        }
                        Err(error) => self.notice = Some((true, error)),
                    }
                }
            }
            Message::CopyPublic => {
                if !self.public_keys.is_empty() {
                    self.notice = Some((false, "Public key copied. It is safe to share.".into()));
                    return iced::clipboard::write(self.public_keys.join("\n"));
                }
            }
            Message::UsePublic if !self.blocked() => {
                self.page = Page::Encrypt;
                self.method = Method::Key;
                self.files.clear();
                self.results.clear();
                self.recipients = shad::textarea::Content::with_text(&self.public_keys.join("\n"));
                self.clear_secrets();
                self.notice = None;
            }
            Message::PickOutput if !self.blocked() => {
                self.picker_open = true;
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Choose output folder")
                            .pick_folder()
                            .await
                            .map(|f| f.path().to_owned())
                    },
                    Message::OutputPicked,
                );
            }
            Message::OutputPicked(path) => {
                self.picker_open = false;
                if let Some(path) = path {
                    self.output = Some(path);
                }
            }
            Message::ResetOutput if !self.blocked() => self.output = None,
            Message::Armor(value) if !self.blocked() => self.armor = value,
            Message::Start
                if !self.blocked() && matches!(self.page, Page::Encrypt | Page::Decrypt) =>
            {
                if let Err(error) = self.validate() {
                    self.notice = Some((true, error));
                    return Task::none();
                }
                let credential = if self.method == Method::Passphrase {
                    Credential::Passphrase(SecretString::from(std::mem::take(&mut *self.password)))
                } else if self.page == Page::Encrypt {
                    Credential::Recipients(self.recipients.text())
                } else {
                    Credential::IdentityFile(self.identity.clone().expect("validated identity"))
                };
                self.clear_secrets();
                let job = Job {
                    operation: self.page.operation(),
                    inputs: self.files.iter().map(|f| f.path.clone()).collect(),
                    output_dir: self.output.clone(),
                    armor: self.armor,
                    credential,
                };
                let progress = Arc::new(Progress::default());
                self.progress = Some(progress.clone());
                self.started_job = Some(Instant::now());
                self.results.clear();
                self.notice = None;
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || crypto::run(job, progress))
                            .await
                            .unwrap_or_else(|_| {
                                vec![FileResult {
                                    input: PathBuf::from("Operation"),
                                    output: None,
                                    error: Some("The worker stopped unexpectedly.".into()),
                                }]
                            })
                    },
                    Message::Finished,
                );
            }
            Message::Cancel => {
                if let Some(progress) = &self.progress {
                    progress.cancelled.store(true, Ordering::Relaxed);
                }
            }
            Message::Finished(results) => {
                self.progress = None;
                self.results = results;
                let ok = self.results.iter().filter(|r| r.output.is_some()).count();
                self.notice = Some((
                    ok != self.results.len(),
                    format!(
                        "{} of {} files {}. Originals are unchanged.",
                        ok,
                        self.results.len(),
                        if self.page == Page::Decrypt {
                            "decrypted"
                        } else {
                            "encrypted"
                        }
                    ),
                ));
                if let Some(id) = self.close_requested.take() {
                    return window::close(id);
                }
            }
            Message::ToggleTheme => self.dark = !self.dark,
            Message::Dismiss => self.notice = None,
            Message::Window(_, window::Event::FileDropped(path)) => {
                self.hovered = false;
                if !self.blocked() {
                    return Task::done(Message::FilesPicked(vec![path]));
                }
            }
            Message::Window(_, window::Event::FileHovered(_)) => self.hovered = true,
            Message::Window(_, window::Event::FilesHoveredLeft) => self.hovered = false,
            Message::Window(id, window::Event::CloseRequested) => {
                if self.busy() {
                    self.close_requested = Some(id);
                } else {
                    self.clear_secrets();
                    return window::close(id);
                }
            }
            Message::Close(id) => {
                self.close_requested = Some(id);
                if let Some(p) = &self.progress {
                    p.cancelled.store(true, Ordering::Relaxed);
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
            Message::Captured(screenshot) => {
                if let Some(dir) = &self.options.probe {
                    let _ = image::save_buffer(
                        dir.join("window.png"),
                        &screenshot.rgba,
                        screenshot.size.width,
                        screenshot.size.height,
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
        Task::none()
    }

    fn validate(&self) -> Result<(), String> {
        if self.files.is_empty() {
            return Err("Choose at least one file to get started.".into());
        }
        if self.method == Method::Passphrase {
            if self.password.is_empty() {
                return Err("Enter your passphrase.".into());
            }
            if self.page == Page::Encrypt {
                if self.password.chars().count() < 12 {
                    return Err(
                        "Use at least 12 characters. A few random words make a good passphrase."
                            .into(),
                    );
                }
                if self.password != self.confirmation {
                    return Err("The passphrases do not match.".into());
                }
            }
        } else if self.page == Page::Encrypt {
            crypto::recipients(&self.recipients.text())?;
        } else if self.identity.is_none() {
            return Err("Choose the secret identity file that can unlock these files.".into());
        }
        Ok(())
    }

    pub fn view(&self) -> Element<'_, Message> {
        let header = container(
            row![
                muted("Workspace", 12),
                muted("/", 12),
                text(self.page.title()).size(12).font(font::medium()),
                space::horizontal(),
                badge("LOCAL ONLY")
                    .variant(shad::badge::Variant::Outline)
                    .icon(lucide::SHIELD_CHECK),
            ]
            .spacing(14)
            .align_y(Alignment::Center),
        )
        .padding([20, 32])
        .width(Length::Fill)
        .style(header_style);

        let content = match self.page {
            Page::Keys => self.keys_view(),
            Page::Guide => self.guide_view(),
            _ => self.workspace_view(),
        };
        let main = column![
            header,
            scrollable(container(content).padding([30, 32]).width(Length::Fill))
                .height(Length::Fill)
        ]
        .width(Length::Fill);
        let shell = row![self.sidebar(), main].height(Length::Fill);
        let base: Element<'_, Message> = container(shell)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(background_style)
            .into();
        if let Some(id) = self.close_requested {
            return tab_order(shad::dialog::dialog(base, true).on_close(Message::Stay)
                .title("An operation is still running")
                .description("You can stay here, or cancel the operation and close once the current file has been cleaned up. Files already completed are kept.")
                .content(row![button("Keep working").variant(shad::button::Variant::Outline).on_press(Message::Stay), button("Cancel and close").on_press(Message::Close(id))].spacing(8))
            ).into();
        }
        // Capture app shortcuts before a focused button consumes Enter. The
        // subscription only handles uncaptured keys (e.g. before initial focus).
        shad::primitive::keys(tab_order(base), shortcut).into()
    }

    fn sidebar(&self) -> Element<'_, Message> {
        let logo = row![
            container(lucide::LOCK_KEYHOLE.sized(20).color(Color::WHITE))
                .padding(10)
                .style(|_| container::Style {
                    background: Some(Background::Color(Color::from_rgb8(24, 24, 27))),
                    border: Border {
                        radius: 11.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            column![
                text("age").size(26).font(font::semibold()),
                muted("FILE ENCRYPTION", 9)
            ]
            .spacing(0)
        ]
        .spacing(11)
        .align_y(Alignment::Center);
        let nav = column![
            nav_item(
                "Encrypt",
                lucide::LOCK_KEYHOLE,
                Page::Encrypt,
                self.page,
                self.blocked()
            ),
            nav_item(
                "Decrypt",
                lucide::LOCK_KEYHOLE_OPEN,
                Page::Decrypt,
                self.page,
                self.blocked()
            ),
            nav_item(
                "Your keys",
                lucide::KEY_ROUND,
                Page::Keys,
                self.page,
                self.blocked()
            ),
        ]
        .spacing(6);
        let bottom = column![
            nav_item(
                "How it works",
                lucide::BOOK_OPEN,
                Page::Guide,
                self.page,
                self.blocked()
            ),
            button(if self.dark {
                "Light appearance"
            } else {
                "Dark appearance"
            })
            .icon(if self.dark { lucide::SUN } else { lucide::MOON })
            .variant(shad::button::Variant::Ghost)
            .width(Length::Fill)
            .on_press(Message::ToggleTheme),
            space::vertical().height(14),
            row![
                text("●").size(10).color(Color::from_rgb8(34, 140, 93)),
                muted("Everything stays here", 11)
            ]
            .spacing(7)
            .align_y(Alignment::Center),
            muted("age desktop  /  0.1.0", 10),
        ]
        .spacing(8);
        container(
            column![
                logo,
                space::vertical().height(40),
                muted("WORKSPACE", 10),
                nav,
                space::vertical(),
                bottom
            ]
            .spacing(12),
        )
        .padding([28, 18])
        .width(210)
        .height(Length::Fill)
        .style(sidebar_style)
        .into()
    }

    fn workspace_view(&self) -> Element<'_, Message> {
        let decrypting = self.page == Page::Decrypt;
        let heading = column![
            text(if decrypting {
                "Back in your hands."
            } else {
                "Keep it between you."
            })
            .font(font::semibold())
            .size(30),
            muted(
                if decrypting {
                    "Unlock your files with a secret identity or passphrase."
                } else {
                    "Simple, secure file encryption. Yours to keep. Yours to share."
                },
                14
            ),
        ]
        .spacing(8);
        let left = column![self.file_card(), self.output_card()]
            .spacing(18)
            .width(Length::FillPortion(6));
        let right = column![self.protection_card(), self.reassurance()]
            .spacing(18)
            .width(Length::FillPortion(5));
        let mut body = column![heading, row![left, right].spacing(22)].spacing(26);
        if let Some((error, notice)) = &self.notice {
            body = body.push(
                alert(if *error {
                    "A little attention needed"
                } else {
                    "All set"
                })
                .description(notice.clone())
                .icon(if *error {
                    lucide::CIRCLE_ALERT
                } else {
                    lucide::CIRCLE_CHECK
                })
                .variant(if *error {
                    shad::alert::Variant::Destructive
                } else {
                    shad::alert::Variant::Default
                })
                .action(
                    icon_button(lucide::X)
                        .size(shad::button::Size::IconXs)
                        .variant(shad::button::Variant::Ghost)
                        .on_press(Message::Dismiss),
                ),
            );
        }
        body = body.push(self.action_bar());
        if !self.results.is_empty() {
            body = body.push(self.results_view());
        }
        body.into()
    }

    fn file_card(&self) -> Element<'_, Message> {
        let mut card = card()
            .title("01   Choose your files")
            .description("Drop files anywhere in this window.")
            .action(badge(self.files.len().to_string()).variant(shad::badge::Variant::Secondary));
        if self.files.is_empty() {
            let drop = column![
                container(lucide::FILES.sized(28))
                    .padding(10)
                    .style(icon_tile_style),
                text(if self.hovered {
                    "Release to add your files"
                } else {
                    "A safe place to drop your files"
                })
                .size(14)
                .font(font::medium()),
                muted(
                    if self.page == Page::Decrypt {
                        "Binary .age or armored files"
                    } else {
                        "Documents, photos, archives, anything."
                    },
                    12
                ),
                button("Browse files")
                    .icon(lucide::PLUS)
                    .variant(shad::button::Variant::Outline)
                    .on_press_maybe((!self.blocked()).then_some(Message::PickFiles)),
            ]
            .spacing(9)
            .align_x(Alignment::Center);
            card = card.content(
                container(drop)
                    .center_x(Length::Fill)
                    .padding([16, 10])
                    .style(drop_style),
            );
        } else {
            let mut files = column![].spacing(4);
            for (i, file) in self.files.iter().enumerate() {
                files = files.push(
                    container(
                        row![
                            container(lucide::FILE.sized(18))
                                .padding(9)
                                .style(icon_tile_style),
                            column![
                                text(filename(&file.path)).size(12).font(font::medium()),
                                muted(format_size(file.size), 11)
                            ]
                            .spacing(3)
                            .width(Length::Fill),
                            icon_button(lucide::X)
                                .size(shad::button::Size::IconSm)
                                .variant(shad::button::Variant::Ghost)
                                .on_press_maybe(
                                    (!self.blocked()).then_some(Message::RemoveFile(i))
                                ),
                        ]
                        .spacing(12)
                        .align_y(Alignment::Center),
                    )
                    .padding([8, 0]),
                );
            }
            card = card
                .content(scrollable(files).height((self.files.len() as f32 * 58.0).min(190.0)))
                .content(
                    row![
                        button("Add files")
                            .icon(lucide::PLUS)
                            .variant(shad::button::Variant::Outline)
                            .on_press_maybe((!self.blocked()).then_some(Message::PickFiles)),
                        space::horizontal(),
                        button("Clear")
                            .variant(shad::button::Variant::Ghost)
                            .on_press_maybe((!self.blocked()).then_some(Message::ClearFiles)),
                    ]
                    .align_y(Alignment::Center),
                );
        }
        card.footer(
            row![
                lucide::HARD_DRIVE.sized(13),
                muted(
                    if self.files.is_empty() {
                        "Files are never uploaded  ·  Ctrl + O to browse".into()
                    } else {
                        format!(
                            "{} files  ·  {}",
                            self.files.len(),
                            format_size(self.total_size())
                        )
                    },
                    11
                )
            ]
            .spacing(7)
            .align_y(Alignment::Center),
        )
        .into()
    }

    fn output_card(&self) -> Element<'_, Message> {
        let location = self
            .output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Next to the original files".into());
        let mut card = card().title("03   Save a new copy").content(
            column![
                row![
                    lucide::FOLDER_OPEN.sized(16),
                    text(location).size(12).width(Length::Fill)
                ]
                .spacing(9),
                row![
                    button("Change folder")
                        .variant(shad::button::Variant::Outline)
                        .size(shad::button::Size::Sm)
                        .on_press_maybe((!self.blocked()).then_some(Message::PickOutput)),
                    button("Reset")
                        .variant(shad::button::Variant::Ghost)
                        .size(shad::button::Size::Sm)
                        .on_press_maybe(
                            (!self.blocked() && self.output.is_some())
                                .then_some(Message::ResetOutput)
                        )
                ]
                .spacing(8),
            ]
            .spacing(12),
        );
        if self.page == Page::Encrypt {
            card = card.content(
                field(
                    "Text-friendly output",
                    switch(self.armor)
                        .on_toggle(Message::Armor)
                        .disabled(self.blocked()),
                )
                .description("ASCII armor for copying into messages.")
                .orientation(shad::field::Orientation::Responsive),
            );
        } else {
            card = card.content(muted("Existing files are never overwritten. Choose a new folder if the original is still there.", 12));
        }
        card.into()
    }

    fn protection_card(&self) -> Element<'_, Message> {
        let encrypting = self.page == Page::Encrypt;
        let tabs = tabs(self.method, Message::Method)
            .tab_with_icon(
                Method::Key,
                lucide::KEY_ROUND,
                if encrypting {
                    "Recipient"
                } else {
                    "Identity file"
                },
            )
            .tab_with_icon(Method::Passphrase, lucide::ASTERISK, "Passphrase")
            .width(Length::Fill);
        let mut fields = column![tabs].spacing(18);
        if self.method == Method::Key && encrypting {
            let value = self.recipients.text();
            let count = crypto::recipients(&value).map(|r| r.len()).ok();
            // The upstream shadcn textarea currently exposes only word wrapping.
            // age keys have no spaces, so use its style on Iced's editor with a
            // glyph fallback to keep the complete key inside narrow layouts.
            let input = widget::text_editor(&self.recipients)
                .placeholder("age1…\n\nOne public key per line")
                .height(118)
                .size(12)
                .font(font::mono())
                .padding([9, 11])
                .wrapping(text::Wrapping::WordOrGlyph)
                .style(|theme, status| shad::textarea::style(theme, status, false));
            fields = fields.push(
                field(
                    "Recipient public keys",
                    if self.blocked() {
                        input
                    } else {
                        input.on_action(Message::Recipients)
                    },
                )
                .description("One age1 public key per recipient."),
            );
            fields = fields.push(if let Some(n) = count {
                row![
                    lucide::CHECK.sized(13),
                    muted(
                        format!("{n} valid recipient{}", if n == 1 { "" } else { "s" }),
                        12
                    )
                ]
                .spacing(7)
            } else {
                row![
                    lucide::INFO.sized(13),
                    muted("Only these recipients can unlock the files.", 12)
                ]
                .spacing(7)
            });
            fields = fields.push(
                button("Need a key? Create one")
                    .variant(shad::button::Variant::Link)
                    .size(shad::button::Size::Sm)
                    .on_press_maybe((!self.blocked()).then_some(Message::Navigate(Page::Keys))),
            );
        } else if self.method == Method::Key {
            fields = fields.push(
                field(
                    "Your secret identity",
                    column![
                        muted(
                            self.identity
                                .as_ref()
                                .map(|p| filename(p))
                                .unwrap_or_else(|| "No identity selected".into()),
                            13
                        ),
                        button("Choose identity file")
                            .icon(lucide::KEY_ROUND)
                            .variant(shad::button::Variant::Outline)
                            .on_press_maybe((!self.blocked()).then_some(Message::PickIdentity)),
                    ]
                    .spacing(12),
                )
                .description("A plain age X25519 identity file, usually saved as .txt or .agekey."),
            );
        } else {
            fields = fields.push(field(
                "Passphrase",
                input("Enter your passphrase", &self.password)
                    .secure(!self.reveal)
                    .on_input_maybe(
                        (!self.blocked()).then_some(|s| Message::Password(Zeroizing::new(s))),
                    ),
            ));
            if encrypting {
                fields = fields.push(
                    field(
                        "Confirm passphrase",
                        input("Enter it once more", &self.confirmation)
                            .secure(!self.reveal)
                            .on_input_maybe(
                                (!self.blocked())
                                    .then_some(|s| Message::Confirm(Zeroizing::new(s))),
                            ),
                    )
                    .description("At least 12 characters. Try a few random words."),
                );
            }
            fields = fields.push(
                button(if self.reveal {
                    "Hide passphrase"
                } else {
                    "Show passphrase"
                })
                .icon(if self.reveal {
                    lucide::EYE_OFF
                } else {
                    lucide::EYE
                })
                .variant(shad::button::Variant::Ghost)
                .size(shad::button::Size::Sm)
                .on_press(Message::Reveal),
            );
        }
        card()
            .title(if encrypting {
                "02   Who can open them?"
            } else {
                "02   Unlock your files"
            })
            .description(if encrypting {
                "Choose how to protect your files."
            } else {
                "Use the key or passphrase used to encrypt."
            })
            .content(fields)
            .into()
    }

    fn reassurance(&self) -> Element<'_, Message> {
        container(
            row![
                lucide::SHIELD_CHECK.sized(18),
                column![
                    text("Private by design").size(13).font(font::medium()),
                    muted(
                        "Encryption happens on your device. No accounts. No uploads. No tracking.",
                        12
                    ),
                ]
                .spacing(7)
            ]
            .spacing(12),
        )
        .padding(17)
        .width(Length::Fill)
        .style(soft_style)
        .into()
    }

    fn action_bar(&self) -> Element<'_, Message> {
        if let Some(p) = &self.progress {
            let cancelling = p.cancelled.load(Ordering::Relaxed);
            let percent = (p.bytes.load(Ordering::Relaxed) as f64 / self.total_size().max(1) as f64
                * 100.0)
                .min(99.0) as f32;
            return column![
                row![
                    text(if cancelling {
                        "Cancelling safely…"
                    } else {
                        "Working on your files…"
                    })
                    .size(13)
                    .font(font::medium()),
                    space::horizontal(),
                    button("Cancel")
                        .variant(shad::button::Variant::Outline)
                        .on_press_maybe((!cancelling).then_some(Message::Cancel))
                ]
                .align_y(Alignment::Center),
                progress(percent)
            ]
            .spacing(12)
            .into();
        }
        row![
            column![
                text("Your originals stay untouched.")
                    .size(13)
                    .font(font::medium()),
                muted("A separate copy. A little more peace of mind.", 12)
            ]
            .spacing(5),
            space::horizontal(),
            button(if self.page == Page::Encrypt {
                "Encrypt files"
            } else {
                "Decrypt files"
            })
            .icon(if self.page == Page::Encrypt {
                lucide::LOCK_KEYHOLE
            } else {
                lucide::LOCK_KEYHOLE_OPEN
            })
            .size(shad::button::Size::Lg)
            .disabled(self.files.is_empty() || self.blocked())
            .on_press_maybe((!self.files.is_empty() && !self.blocked()).then_some(Message::Start)),
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .into()
    }

    fn results_view(&self) -> Element<'_, Message> {
        let mut results = column![].spacing(14);
        for result in &self.results {
            let detail = result
                .output
                .as_ref()
                .map(|p| format!("Saved to {}", p.display()))
                .unwrap_or_else(|| result.error.clone().unwrap_or_default());
            results = results.push(
                row![
                    if result.output.is_some() {
                        lucide::CIRCLE_CHECK
                            .sized(16)
                            .color(Color::from_rgb8(34, 140, 93))
                    } else {
                        lucide::CIRCLE_ALERT
                            .sized(16)
                            .color(Color::from_rgb8(220, 60, 60))
                    },
                    column![
                        text(filename(&result.input)).size(13).font(font::medium()),
                        muted(detail, 12)
                    ]
                    .spacing(4),
                ]
                .spacing(10),
            );
        }
        card()
            .title("Results")
            .description("This list is kept only for the current session.")
            .content(results)
            .into()
    }

    fn keys_view(&self) -> Element<'_, Message> {
        let mut body = column![
            text("One key. Only yours.").size(30).font(font::semibold()),
            muted("Create an identity to receive encrypted files, or open one you already have.", 14),
            space::vertical().height(10),
            card().title("A key with two sides").description("Share the public key. Keep the secret identity file private.")
                .content(row![
                    key_explainer(lucide::SEND, "Public key", "Give this to someone who wants to send you a file. It starts with age1."),
                    key_explainer(lucide::KEY_ROUND, "Secret identity", "This file unlocks your encrypted files. Back it up somewhere only you can access."),
                ].spacing(28))
                .footer(row![button("Create a new identity").icon(lucide::PLUS).on_press_maybe((!self.blocked()).then_some(Message::GenerateKey)),
                    button("Open an existing identity").icon(lucide::FOLDER_OPEN).variant(shad::button::Variant::Outline).on_press_maybe((!self.blocked()).then_some(Message::PickIdentity))].spacing(10)),
        ].spacing(14);
        if !self.public_keys.is_empty() {
            let mut keys = column![].spacing(10);
            for key in &self.public_keys {
                keys = keys.push(text(key.clone()).size(12).font(font::mono()));
            }
            body = body.push(
                card()
                    .title("Your public key")
                    .description("Safe to copy and share.")
                    .content(keys)
                    .content(muted(
                        format!(
                            "Identity file: {}",
                            self.identity.as_ref().unwrap().display()
                        ),
                        12,
                    ))
                    .footer(
                        row![
                            button("Copy public key")
                                .icon(lucide::COPY)
                                .on_press(Message::CopyPublic),
                            button("Encrypt to myself")
                                .variant(shad::button::Variant::Outline)
                                .on_press(Message::UsePublic)
                        ]
                        .spacing(10),
                    ),
            );
        }
        if let Some((error, notice)) = &self.notice {
            body = body.push(
                alert(if *error {
                    "Could not open the key"
                } else {
                    "Ready"
                })
                .description(notice.clone())
                .variant(if *error {
                    shad::alert::Variant::Destructive
                } else {
                    shad::alert::Variant::Default
                }),
            );
        }
        body.push(self.reassurance()).into()
    }

    fn guide_view(&self) -> Element<'_, Message> {
        column![
            text("A little peace of mind.").size(30).font(font::semibold()),
            muted("A native desktop companion for the open age encryption format.", 14),
            space::vertical().height(10),
            card().title("Sending a file").content(muted("Ask the recipient for their public key. Add your files in Encrypt, paste the public key, and encrypt. Share the new .age files however you like. Add your own public key too if you want to decrypt them later.", 14)),
            card().title("Using a passphrase").content(muted("Choose a strong passphrase, then send it through a different channel from the encrypted file. You will need the exact same passphrase to decrypt. There is no password reset.", 14)),
            card().title("What this version supports").content(muted("X25519 age recipients and identities, passphrases, multiple files, and ASCII armor. SSH keys, encrypted identity files, plugins, and post-quantum keys are not supported yet. Archive folders before encrypting them.", 14)),
            card().title("Made to stay local").content(muted("Built with Rust, Iced, shadcn-iced, and the age library from rage. Files and passphrases are never sent over a network. Secret identities are saved only to a location you choose. This app has not undergone an independent security audit.", 14))
                .footer(muted("age desktop is an independent project; it is not an official age application.", 12)),
            row![badge("Native Rust").variant(shad::badge::Variant::Outline), badge("CPU + GPU rendering").variant(shad::badge::Variant::Outline), badge("age format").variant(shad::badge::Variant::Outline)].spacing(8),
        ].spacing(16).into()
    }
}

fn shortcut(key: &iced::keyboard::Key, modifiers: iced::keyboard::Modifiers) -> Option<Message> {
    if !modifiers.command() {
        return None;
    }
    match key.as_ref() {
        iced::keyboard::Key::Character("o") => Some(Message::PickFiles),
        iced::keyboard::Key::Character("1") => Some(Message::Navigate(Page::Encrypt)),
        iced::keyboard::Key::Character("2") => Some(Message::Navigate(Page::Decrypt)),
        iced::keyboard::Key::Character("3") => Some(Message::Navigate(Page::Keys)),
        iced::keyboard::Key::Named(iced::keyboard::key::Named::Enter) => Some(Message::Start),
        _ => None,
    }
}

fn filename(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
fn muted<'a>(value: impl text::IntoFragment<'a>, size: u32) -> widget::Text<'a> {
    text(value)
        .size(size)
        .wrapping(text::Wrapping::WordOrGlyph)
        .style(|t: &Theme| text::Style {
            color: Some(tokens(t).palette.muted_foreground),
        })
}
fn nav_item(
    label: &str,
    icon: shad::Icon,
    page: Page,
    current: Page,
    disabled: bool,
) -> Element<'_, Message> {
    shad::button::Button::new(
        row![icon.sized(16), text(label).size(14).font(font::medium())]
            .spacing(10)
            .width(Length::Fill),
    )
    .size(shad::button::Size::Lg)
    .width(Length::Fill)
    .variant(if page == current {
        shad::button::Variant::Secondary
    } else {
        shad::button::Variant::Ghost
    })
    .on_press_maybe((!disabled).then_some(Message::Navigate(page)))
    .into()
}
fn key_explainer(
    icon: shad::Icon,
    title: &'static str,
    description: &'static str,
) -> Element<'static, Message> {
    column![
        container(icon.sized(22)).padding(12).style(icon_tile_style),
        text(title).size(15).font(font::medium()),
        muted(description, 13)
    ]
    .spacing(12)
    .width(Length::Fill)
    .into()
}
fn background_style(t: &Theme) -> container::Style {
    let p = tokens(t).palette;
    container::Style {
        background: Some(p.background.into()),
        text_color: Some(p.foreground),
        ..Default::default()
    }
}
fn sidebar_style(t: &Theme) -> container::Style {
    let p = tokens(t).palette;
    container::Style {
        background: Some(p.card.into()),
        border: Border {
            color: p.border,
            width: 1.0,
            ..Default::default()
        },
        ..Default::default()
    }
}
fn header_style(t: &Theme) -> container::Style {
    sidebar_style(t)
}
fn icon_tile_style(t: &Theme) -> container::Style {
    let p = tokens(t).palette;
    container::Style {
        background: Some(p.muted.into()),
        border: Border {
            radius: 10.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}
fn soft_style(t: &Theme) -> container::Style {
    icon_tile_style(t)
}
fn drop_style(t: &Theme) -> container::Style {
    let p = tokens(t).palette;
    container::Style {
        background: Some(p.background.into()),
        border: Border {
            radius: 9.0.into(),
            color: p.border,
            width: 1.0,
        },
        ..Default::default()
    }
}
