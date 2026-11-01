use super::*;
use iced::widget::{self, column, container, row, scrollable, space, text};
use iced::{Alignment, Background, Border, Color, Length};
use shadcn_iced::prelude::*;
use shadcn_iced::{font, tokens};
use std::sync::atomic::Ordering;

impl App {
    pub fn view(&self) -> Element<'_, Message> {
        let header = container(
            row![
                muted("Workspace", 12),
                muted("/", 12),
                text(self.page.title()).size(12).font(font::medium()),
                space::horizontal(),
                badge("LOCAL ENCRYPTION")
                    .variant(shad::badge::Variant::Outline)
                    .icon(lucide::SHIELD_CHECK)
            ]
            .spacing(14)
            .align_y(Alignment::Center),
        )
        .padding([19, 30])
        .width(Length::Fill)
        .style(sidebar_style);
        let content = match self.page {
            Page::Encrypt | Page::Decrypt => self.workspace_view(),
            Page::Keys => self.keys_view(),
            Page::Inspect => self.inspect_view(),
            Page::Settings => self.settings_view(),
            Page::Guide => self.guide_view(),
        };
        let mut body = column![content].spacing(20);
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
        if self.working() && !self.results.is_empty() {
            body = body.push(self.results_view());
        }
        let mut main = column![
            header,
            scrollable(container(body).padding([26, 30]).width(Length::Fill))
                .id("workspace-scroll")
                .height(Length::Fill)
        ]
        .width(Length::Fill);
        if self.working() || self.busy() {
            main = main.push(
                container(self.action_bar())
                    .padding([18, 30])
                    .width(Length::Fill)
                    .style(sidebar_style),
            );
        }
        let base: Element<'_, Message> = container(row![self.sidebar(), main].height(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(background_style)
            .into();
        if let Some(id) = self.close_requested {
            return tab_order(shad::dialog::dialog(base,true).title("An operation is still running").description("Cancel and close after the engine and its plugins stop. Incomplete output is removed; completed files are kept.").on_close(Message::Stay).footer(row![button("Keep working").variant(shad::button::Variant::Outline).on_press(Message::Stay),button("Cancel and close").on_press(Message::Close(id))].spacing(8))).into();
        }
        if let Some(prompt) = &self.prompt {
            let mut dialog = shad::dialog::dialog(base, true)
                .title(if prompt.secret {
                    "Unlock to continue"
                } else {
                    "Plugin confirmation"
                })
                .description(prompt.message.clone())
                .width(520.0)
                .on_close(Message::Cancel);
            if prompt.yes.is_empty() {
                dialog = dialog.content(
                    input(
                        if prompt.secret {
                            "Passphrase or PIN"
                        } else {
                            "Enter the requested value"
                        },
                        &self.prompt_value,
                    )
                    .secure(prompt.secret)
                    .on_input(|s| Message::PromptValue(Zeroizing::new(s)))
                    .on_submit(Message::PromptReply(true)),
                );
            }
            let mut actions = row![
                button("Cancel operation")
                    .variant(shad::button::Variant::Outline)
                    .on_press(Message::Cancel),
                space::horizontal(),
                button(if prompt.yes.is_empty() {
                    "Continue"
                } else {
                    &prompt.yes
                })
                .on_press(Message::PromptReply(true))
            ];
            if !prompt.no.is_empty() {
                actions = actions.push(
                    button(prompt.no.clone())
                        .variant(shad::button::Variant::Outline)
                        .on_press(Message::PromptReply(false)),
                );
            }
            return tab_order(dialog.footer(actions.spacing(8))).into();
        }
        if self.confirm_replace {
            let mut targets = column![].spacing(7);
            for file in &self.files {
                let path = self.output_file.clone().or_else(|| {
                    crypto::output_path(
                        &file.path,
                        self.output_dir.as_deref(),
                        self.operation,
                        self.armor,
                    )
                    .ok()
                });
                if let Some(path) = path {
                    targets = targets.push(muted(path.display().to_string(), 12));
                }
            }
            return tab_order(shad::dialog::dialog(base,true).title("Allow replacing these output files?").description("Existing outputs at the paths below may be replaced. Your input files and selected key files are protected. Completed outputs are kept if you cancel a batch.").content(scrollable(targets).height(180)).width(600.0).on_close(Message::ConfirmReplace(false)).footer(row![button("Go back").variant(shad::button::Variant::Outline).on_press(Message::ConfirmReplace(false)),space::horizontal(),button("Replace outputs and continue").on_press(Message::ConfirmReplace(true))].spacing(8))).into();
        }
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
        let navigation = column![
            nav("Encrypt", lucide::LOCK_KEYHOLE, Page::Encrypt, self),
            nav("Decrypt", lucide::LOCK_KEYHOLE_OPEN, Page::Decrypt, self),
            nav("Your keys", lucide::KEY_ROUND, Page::Keys, self),
            nav("Inspect", lucide::SCAN_SEARCH, Page::Inspect, self)
        ]
        .spacing(6);
        let bottom = column![
            nav("Tools & settings", lucide::SETTINGS_2, Page::Settings, self),
            nav("How it works", lucide::BOOK_OPEN, Page::Guide, self),
            button(if self.dark {
                "Light appearance"
            } else {
                "Dark appearance"
            })
            .icon(if self.dark { lucide::SUN } else { lucide::MOON })
            .variant(shad::button::Variant::Ghost)
            .width(Length::Fill)
            .on_press(Message::ToggleTheme),
            space::vertical().height(12),
            row![
                text("●").size(10).color(Color::from_rgb8(34, 140, 93)),
                muted("Everything stays here", 11)
            ]
            .spacing(7)
            .align_y(Alignment::Center),
            muted("age desktop  /  0.2.0", 10)
        ]
        .spacing(7);
        container(
            column![
                logo,
                space::vertical().height(30),
                muted("WORKSPACE", 10),
                navigation,
                space::vertical(),
                bottom
            ]
            .spacing(12),
        )
        .padding([27, 18])
        .width(210)
        .height(Length::Fill)
        .style(sidebar_style)
        .into()
    }
    fn workspace_view(&self) -> Element<'_, Message> {
        let decrypting = self.operation == Operation::Decrypt;
        let heading = column![
            text(if decrypting {
                "Back in your hands."
            } else {
                "Your files. Your choice."
            })
            .size(29)
            .font(font::semibold()),
            muted(
                if decrypting {
                    "Unlock files or text. Password-protected inputs are detected automatically."
                } else {
                    "Choose how to protect your data, and who can open it."
                },
                14
            )
        ]
        .spacing(7);
        let modes = tabs(self.input_mode, Message::InputMode)
            .tab_with_icon(InputMode::Files, lucide::FILES, "Files")
            .tab_with_icon(InputMode::Text, lucide::TEXT, "Text & clipboard");
        let left = column![self.input_card(), self.output_card()]
            .spacing(18)
            .width(Length::FillPortion(6));
        let right = column![self.protection_card(), self.reassurance()]
            .spacing(18)
            .width(Length::FillPortion(5));
        let mut body = column![
            row![heading, space::horizontal(), modes]
                .spacing(18)
                .align_y(Alignment::Center),
            row![left, right].spacing(20)
        ]
        .spacing(24);
        if self.input_mode == InputMode::Text && !self.text_output.is_empty() {
            body = body.push(
                card()
                    .title(if decrypting {
                        "Decrypted text"
                    } else {
                        "Encrypted text"
                    })
                    .description("Kept in memory for this session.")
                    .content(
                        scrollable(
                            text(self.text_output.as_str())
                                .font(font::mono())
                                .size(12)
                                .wrapping(text::Wrapping::WordOrGlyph),
                        )
                        .height(160),
                    )
                    .footer(
                        row![
                            button("Copy result")
                                .icon(lucide::COPY)
                                .on_press(Message::CopyText),
                            button("Save result")
                                .icon(lucide::SAVE)
                                .variant(shad::button::Variant::Outline)
                                .on_press(Message::Pick(Pick::TextSave)),
                            button(if decrypting {
                                "Encrypt this text"
                            } else {
                                "Decrypt this text"
                            })
                            .variant(shad::button::Variant::Ghost)
                            .on_press(Message::UseTextOutput)
                        ]
                        .spacing(8),
                    ),
            );
        }
        body = body.push(collapsible(
            "Equivalent age command",
            column![
                muted(
                    "PowerShell example. Replace filename placeholders for Text mode. Passwords and secret identities are omitted.",
                    12
                ),
                container(
                    text(self.cli_preview())
                        .font(font::mono())
                        .size(11)
                        .wrapping(text::Wrapping::WordOrGlyph)
                )
                .padding(12)
                .width(Length::Fill)
                .style(soft_style),
                button("Copy command")
                    .icon(lucide::COPY)
                    .variant(shad::button::Variant::Outline)
                    .size(shad::button::Size::Sm)
                    .on_press(Message::CopyCommand)
            ]
            .spacing(10),
        ));
        body.into()
    }
    fn input_card(&self) -> Element<'_, Message> {
        if self.input_mode == InputMode::Text {
            return card()
                .title("01   Add your text")
                .description(if self.operation == Operation::Encrypt {
                    "Plain text, a note, or a secret you want to share."
                } else {
                    "Paste an ASCII-armored age message."
                })
                .content(editor(
                    &self.text_input,
                    if self.operation == Operation::Encrypt {
                        "Type or paste your message…"
                    } else {
                        "-----BEGIN AGE ENCRYPTED FILE-----\n…"
                    },
                    190,
                    self.blocked(),
                    Message::TextEdit,
                ))
                .footer(
                    row![
                        button("Paste text")
                            .icon(lucide::CLIPBOARD_PASTE)
                            .variant(shad::button::Variant::Outline)
                            .size(shad::button::Size::Sm)
                            .disabled(self.blocked())
                            .on_press(Message::PasteText),
                        space::horizontal(),
                        muted("Local session only", 11)
                    ]
                    .align_y(Alignment::Center),
                )
                .into();
        }
        let mut c = card()
            .title("01   Choose your files")
            .description("Drop files into the window, or browse.")
            .action(badge(self.files.len().to_string()).variant(shad::badge::Variant::Secondary));
        if self.files.is_empty() {
            c = c.content(
                container(
                    column![
                        container(lucide::FILES.sized(27))
                            .padding(11)
                            .style(soft_style),
                        text(if self.hovered {
                            "Release to add your files"
                        } else {
                            "A safe place for your files"
                        })
                        .size(14)
                        .font(font::medium()),
                        muted("Documents, photos, archives, anything.", 12),
                        button("Browse files")
                            .icon(lucide::PLUS)
                            .variant(shad::button::Variant::Outline)
                            .disabled(self.blocked())
                            .on_press(Message::Pick(Pick::Inputs))
                    ]
                    .spacing(11)
                    .align_x(Alignment::Center),
                )
                .center_x(Length::Fill)
                .padding([20, 10])
                .style(outline_style),
            );
        } else {
            let mut list = column![].spacing(8);
            for (i, file) in self.files.iter().enumerate() {
                list = list.push(
                    row![
                        container(lucide::FILE.sized(17))
                            .padding(9)
                            .style(soft_style),
                        column![
                            text(filename(&file.path))
                                .size(12)
                                .font(font::medium())
                                .wrapping(text::Wrapping::WordOrGlyph),
                            muted(format_size(file.size), 11)
                        ]
                        .spacing(4)
                        .width(Length::Fill),
                        remove_button(Pick::Inputs, i, self.blocked())
                    ]
                    .spacing(10)
                    .align_y(Alignment::Center),
                );
            }
            c = c
                .content(scrollable(list).height((self.files.len() as f32 * 52.0).min(180.0)))
                .content(row![
                    button("Add files")
                        .icon(lucide::PLUS)
                        .variant(shad::button::Variant::Outline)
                        .size(shad::button::Size::Sm)
                        .disabled(self.blocked())
                        .on_press(Message::Pick(Pick::Inputs)),
                    space::horizontal(),
                    button("Clear")
                        .variant(shad::button::Variant::Ghost)
                        .size(shad::button::Size::Sm)
                        .disabled(self.blocked())
                        .on_press(Message::ClearFiles)
                ]);
        }
        c.footer(
            row![
                lucide::HARD_DRIVE.sized(13),
                muted(
                    if self.files.is_empty() {
                        "Files are never uploaded · Ctrl + O".into()
                    } else {
                        format!(
                            "{} {} · {}",
                            self.files.len(),
                            if self.files.len() == 1 {
                                "file"
                            } else {
                                "files"
                            },
                            format_size(self.size())
                        )
                    },
                    11
                )
            ]
            .spacing(7),
        )
        .into()
    }
    fn output_card(&self) -> Element<'_, Message> {
        if self.input_mode == InputMode::Text {
            return card().title("03   Get the result").description("Encrypted text uses ASCII armor automatically.").content(muted("The result appears below when the operation finishes. Copy it, save it to a file, or switch straight to decryption. Use Files for binary data and large inputs.",12)).into();
        }
        let location = self
            .output_file
            .as_ref()
            .or(self.output_dir.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Next to the original files".into());
        let mut c = card()
            .title("03   Choose the output")
            .content(row![lucide::FOLDER_OPEN.sized(16), muted(location, 12)].spacing(9))
            .content(
                row![
                    button("Folder")
                        .icon(lucide::FOLDER_OPEN)
                        .variant(shad::button::Variant::Outline)
                        .size(shad::button::Size::Sm)
                        .disabled(self.blocked())
                        .on_press(Message::Pick(Pick::OutputDir)),
                    button("Save as…")
                        .variant(shad::button::Variant::Outline)
                        .size(shad::button::Size::Sm)
                        .disabled(self.blocked() || self.files.len() != 1)
                        .on_press(Message::Pick(Pick::OutputFile)),
                    button("Reset")
                        .variant(shad::button::Variant::Ghost)
                        .size(shad::button::Size::Sm)
                        .disabled(self.blocked())
                        .on_press(Message::ResetOutput)
                ]
                .spacing(6),
            );
        if self.operation == Operation::Encrypt {
            c = c.content(
                field(
                    "Text-friendly output",
                    switch(self.armor)
                        .on_toggle(Message::Armor)
                        .disabled(self.blocked()),
                )
                .description("ASCII armor (.age.txt) instead of binary .age.")
                .orientation(shad::field::Orientation::Responsive),
            );
        }
        c.content(
            field(
                "Replace existing outputs",
                switch(self.overwrite)
                    .on_toggle(Message::Overwrite)
                    .disabled(self.blocked()),
            )
            .description("Off by default. You'll confirm the destination paths.")
            .orientation(shad::field::Orientation::Responsive),
        )
        .into()
    }
    fn protection_card(&self) -> Element<'_, Message> {
        let encrypting = self.operation == Operation::Encrypt;
        let mut content = column![].spacing(16);
        if encrypting {
            let mut choices = select(Some(self.protection), Message::Protection)
                .width(Length::Fill)
                .disabled(self.blocked());
            for p in Protection::ALL {
                choices = choices.option(p, p.label());
            }
            content = content.push(field("Encryption protection", choices)).push(
                container(muted(self.protection.help(), 12))
                    .padding(12)
                    .width(Length::Fill)
                    .style(soft_style),
            );
            if self.protection == Protection::Passphrase {
                content = content.push(self.password_fields(SecretTarget::File, true));
            } else {
                content = content.push(field(
                    "Recipient public keys",
                    editor(
                        &self.recipients,
                        match self.protection {
                            Protection::Pq => "age1pq1…\n\nOne public key per line",
                            Protection::Ssh => "ssh-ed25519 AAAA…\nssh-rsa AAAA…",
                            Protection::Plugin => "age1yubikey1… or another plugin key",
                            _ => "age1…\n\nOne public key per line",
                        },
                        102,
                        self.blocked(),
                        Message::Recipients,
                    ),
                ));
                content = content.push(
                    row![
                        button("Import recipient files")
                            .icon(lucide::FILE_PLUS)
                            .variant(shad::button::Variant::Outline)
                            .size(shad::button::Size::Sm)
                            .disabled(self.blocked())
                            .on_press(Message::Pick(Pick::Recipients)),
                        button("Create a key")
                            .variant(shad::button::Variant::Link)
                            .size(shad::button::Size::Sm)
                            .disabled(self.blocked())
                            .on_press(Message::Navigate(Page::Keys))
                    ]
                    .spacing(6),
                );
                if !self.recipient_files.is_empty() {
                    content = content.push(path_list(
                        &self.recipient_files,
                        Pick::Recipients,
                        self.blocked(),
                    ));
                }
                content = content.push(collapsible(
                    "Use my identities / plugins",
                    self.identity_controls(true),
                ));
                if !self.identities.is_empty()
                    || !self.identity_text.is_empty()
                    || !self.plugin_names.is_empty()
                {
                    content = content.push(muted(
                        format!(
                            "Also using {} identity file(s){}{}",
                            self.identities.len(),
                            if self.identity_text.is_empty() {
                                ""
                            } else {
                                " + pasted identity"
                            },
                            if self.plugin_names.is_empty() {
                                ""
                            } else {
                                " + named plugin"
                            }
                        ),
                        11,
                    ));
                }
            }
        } else {
            content=content.push(container(row![lucide::SCAN_SEARCH.sized(18),muted("Age detects the protection and ASCII armor. Passwords, key-file passwords, and plugin PINs are requested when needed.",12)].spacing(10)).padding(12).width(Length::Fill).style(soft_style));
            content = content.push(self.identity_controls(false));
            content = content.push(collapsible(
                "Provide a file passphrase now",
                self.password_fields(SecretTarget::File, false),
            ));
            content = content.push(
                button("Inspect encryption details")
                    .icon(lucide::SCAN_SEARCH)
                    .variant(shad::button::Variant::Outline)
                    .size(shad::button::Size::Sm)
                    .disabled(self.blocked())
                    .on_press(Message::InspectInput),
            );
        }
        card().title(if encrypting{"02   Choose your protection"}else{"02   Unlock your data"}).description(if encrypting{"The key type controls who can decrypt."}else{"Add any identities that may unlock the input."}).content(content).footer(muted("File contents use ChaCha20-Poly1305. Age does not offer a configurable payload cipher.",11)).into()
    }
    fn identity_controls(&self, encrypting: bool) -> Element<'_, Message> {
        let mut content=column![muted(if encrypting{"Encrypt to the public recipients of these identities, including your own key files."}else{"Native, post-quantum, SSH, protected age identities, and plugin identities are supported."},12),row![button("Add identity files").icon(lucide::KEY_ROUND).variant(shad::button::Variant::Outline).size(shad::button::Size::Sm).disabled(self.blocked()).on_press(Message::Pick(Pick::Identities)),button("Paste identity").icon(lucide::CLIPBOARD_PASTE).variant(shad::button::Variant::Ghost).size(shad::button::Size::Sm).disabled(self.blocked()).on_press(Message::PasteIdentity)].spacing(6)].spacing(10);
        if !self.identities.is_empty() {
            content = content.push(path_list(
                &self.identities,
                Pick::Identities,
                self.blocked(),
            ));
        }
        if !self.identity_text.is_empty() {
            content = content.push(
                row![
                    badge("Pasted secret · hidden").variant(shad::badge::Variant::Secondary),
                    button("Clear")
                        .variant(shad::button::Variant::Ghost)
                        .size(shad::button::Size::Xs)
                        .disabled(self.blocked())
                        .on_press(Message::ClearIdentity)
                ]
                .spacing(8),
            );
        }
        content.push(field("Plugin name (optional)",input("Plugin name · comma-separated for multiple",&self.plugin_names).on_input_maybe((!self.blocked()).then_some(Message::PluginNames))).description("For plugins that use -j instead of a key file. Choose an installed plugin folder in Tools & settings.")).into()
    }
    fn password_fields(&self, target: SecretTarget, confirmation: bool) -> Element<'_, Message> {
        let (password, confirm, reveal) = if target == SecretTarget::Key {
            (&self.key_password, &self.key_confirmation, self.key_reveal)
        } else {
            (&self.password, &self.confirmation, self.reveal)
        };
        let mut content = column![field(
            "Passphrase",
            input(
                if confirmation {
                    "Enter or generate a strong passphrase"
                } else {
                    "Optional; otherwise you'll be prompted"
                },
                password
            )
            .secure(!reveal)
            .on_input_maybe(
                (!self.blocked()).then_some(move |s| Message::Password(target, Zeroizing::new(s)))
            )
        )]
        .spacing(12);
        if confirmation {
            content = content.push(field(
                "Confirm passphrase",
                input("Enter it once more", confirm)
                    .secure(!reveal)
                    .on_input_maybe(
                        (!self.blocked())
                            .then_some(move |s| Message::Confirm(target, Zeroizing::new(s))),
                    ),
            ));
        }
        let mut actions = row![
            button(if reveal { "Hide" } else { "Show" })
                .icon(if reveal { lucide::EYE_OFF } else { lucide::EYE })
                .variant(shad::button::Variant::Ghost)
                .size(shad::button::Size::Sm)
                .on_press(Message::Reveal(target))
        ]
        .spacing(8);
        if confirmation {
            actions = actions.push(
                button("Generate secure passphrase")
                    .icon(lucide::DICES)
                    .variant(shad::button::Variant::Outline)
                    .size(shad::button::Size::Sm)
                    .disabled(self.blocked())
                    .on_press(Message::GeneratePassword(target)),
            );
        }
        content.push(actions).into()
    }
    fn reassurance(&self) -> Element<'_, Message> {
        container(
            row![
                lucide::SHIELD_CHECK.sized(18),
                column![
                    text("Official age. Local to your device.")
                        .size(12)
                        .font(font::medium()),
                    muted(
                        "Your files stay here. No account, uploads, or background engine service.",
                        11
                    )
                ]
                .spacing(6)
            ]
            .spacing(11),
        )
        .padding(15)
        .width(Length::Fill)
        .style(soft_style)
        .into()
    }
    fn action_bar(&self) -> Element<'_, Message> {
        if let Some(p) = &self.progress {
            let cancelling = p.is_cancelled();
            let fraction = (p.bytes.load(Ordering::Relaxed) as f64 / self.size().max(1) as f64
                * 100.0)
                .min(99.0) as f32;
            return column![
                row![
                    column![
                        text(if cancelling {
                            "Cancelling safely…"
                        } else {
                            &self.task_title
                        })
                        .size(13)
                        .font(font::medium()),
                        muted(
                            if self.status.is_empty() {
                                "Large files and key derivation run in the background."
                            } else {
                                &self.status
                            },
                            11
                        )
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                    button("Cancel")
                        .variant(shad::button::Variant::Outline)
                        .disabled(cancelling)
                        .on_press(Message::Cancel)
                ]
                .spacing(12)
                .align_y(Alignment::Center),
                progress(fraction)
            ]
            .spacing(10)
            .into();
        }
        let noun = if self.input_mode == InputMode::Text {
            "text"
        } else {
            "files"
        };
        let label = format!(
            "{} {noun}",
            if self.operation == Operation::Encrypt {
                "Encrypt"
            } else {
                "Decrypt"
            }
        );
        row![
            column![
                text("Your originals stay untouched.")
                    .size(13)
                    .font(font::medium()),
                muted(
                    if self.overwrite && self.input_mode == InputMode::Files {
                        "Output replacement is enabled; you'll confirm the paths."
                    } else {
                        "A separate result. Ctrl + Enter to start."
                    },
                    11
                )
            ]
            .spacing(5),
            space::horizontal(),
            button(label)
                .icon(if self.operation == Operation::Encrypt {
                    lucide::LOCK_KEYHOLE
                } else {
                    lucide::LOCK_KEYHOLE_OPEN
                })
                .size(shad::button::Size::Lg)
                .disabled(
                    self.blocked()
                        || (self.input_mode == InputMode::Files && self.files.is_empty())
                )
                .on_press(Message::Start)
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .into()
    }
    fn results_view(&self) -> Element<'_, Message> {
        let mut content = column![].spacing(14);
        for r in &self.results {
            content = content.push(
                row![
                    if r.output.is_some() {
                        lucide::CIRCLE_CHECK
                            .sized(16)
                            .color(Color::from_rgb8(34, 140, 93))
                    } else {
                        lucide::CIRCLE_ALERT
                            .sized(16)
                            .color(Color::from_rgb8(220, 60, 60))
                    },
                    column![
                        text(filename(&r.input)).size(13).font(font::medium()),
                        muted(
                            r.output
                                .as_ref()
                                .map(|p| format!("Saved to {}", p.display()))
                                .unwrap_or_else(|| r.error.clone().unwrap_or_default()),
                            12
                        )
                    ]
                    .spacing(4)
                    .width(Length::Fill)
                ]
                .spacing(10),
            );
        }
        card()
            .title("Results")
            .description(
                "Each file is processed independently. This list is kept only for this session.",
            )
            .content(content)
            .into()
    }
    fn keys_view(&self) -> Element<'_, Message> {
        let kind = select(Some(self.key_kind), Message::KeyKind)
            .option(KeyKind::Pq, "Post-quantum · ML-KEM-768 + X25519")
            .option(KeyKind::Classic, "Classic · X25519")
            .width(Length::Fill)
            .disabled(self.blocked());
        let mut creation = column![
            field("Identity type", kind).description(if self.key_kind == KeyKind::Pq {
                "Recommended for new use with age 1.3+. The public key is longer."
            } else {
                "A compact key compatible with older age tools."
            }),
            field(
                "Protect the identity with a passphrase",
                switch(self.protect_key)
                    .on_toggle(Message::ProtectKey)
                    .disabled(self.blocked())
            )
            .description("Useful when the key file is stored elsewhere. Keep a backup.")
            .orientation(shad::field::Orientation::Responsive)
        ]
        .spacing(18);
        if self.protect_key {
            creation = creation.push(self.password_fields(SecretTarget::Key, true));
        }
        let left = card()
            .title("Create a new identity")
            .description("A public recipient to share. A secret identity to keep.")
            .content(creation)
            .footer(
                button("Create & save identity")
                    .icon(lucide::PLUS)
                    .disabled(self.blocked())
                    .on_press(Message::Pick(Pick::KeySave)),
            );
        let right=card().title("Open existing identities").description("Use your native, post-quantum, SSH, or protected key files.").content(muted("You can open multiple files together. The app extracts their public recipients and asks for passwords only when required.",13)).footer(button("Open identity files").icon(lucide::FOLDER_OPEN).variant(shad::button::Variant::Outline).disabled(self.blocked()).on_press(Message::Pick(Pick::KeyOpen)));
        let mut body = column![
            heading(
                "Keys for every kind of future.",
                "Choose a native key type, protect a key file, or export public recipients."
            ),
            row![
                container(left).width(Length::FillPortion(6)),
                container(right).width(Length::FillPortion(5))
            ]
            .spacing(20)
        ]
        .spacing(24);
        if !self.public_keys.is_empty() {
            body = body.push(
                card()
                    .title("Your public recipients")
                    .description("Safe to share. The secret identity is never displayed.")
                    .content(
                        scrollable(
                            text(self.public_keys.join("\n\n"))
                                .font(font::mono())
                                .size(11)
                                .wrapping(text::Wrapping::WordOrGlyph),
                        )
                        .height(115),
                    )
                    .content(muted(
                        self.key_paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join("\n"),
                        11,
                    ))
                    .footer(
                        row![
                            button("Copy public keys")
                                .icon(lucide::COPY)
                                .on_press(Message::CopyPublic),
                            button("Export recipients file")
                                .icon(lucide::SAVE)
                                .variant(shad::button::Variant::Outline)
                                .on_press(Message::Pick(Pick::PublicSave)),
                            button("Encrypt to myself")
                                .variant(shad::button::Variant::Ghost)
                                .on_press(Message::UsePublic)
                        ]
                        .spacing(8),
                    ),
            );
        }
        body.push(self.reassurance()).into()
    }
    fn inspect_view(&self) -> Element<'_, Message> {
        let mut body = column![
            heading(
                "Know what you're holding.",
                "Inspect encryption metadata without opening the contents."
            ),
            card()
                .title("Choose an encrypted file")
                .description("Binary .age and ASCII-armored files are detected automatically.")
                .content(
                    row![
                        button("Choose file")
                            .icon(lucide::SCAN_SEARCH)
                            .disabled(self.blocked())
                            .on_press(Message::Pick(Pick::Inspect)),
                        muted(
                            self.inspect_path
                                .as_ref()
                                .map(|p| filename(p))
                                .unwrap_or_else(|| {
                                    "Or use Inspect encryption details from the Decrypt view."
                                        .into()
                                }),
                            12
                        )
                    ]
                    .spacing(15)
                    .align_y(Alignment::Center)
                )
        ]
        .spacing(24);
        if let Some(data) = &self.inspection {
            let kinds = data["stanza_types"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let sizes = &data["sizes"];
            let list = column![
                info_row(
                    "Format",
                    data["version"].as_str().unwrap_or("Unknown").into()
                ),
                info_row("Recipient stanza types", kinds),
                info_row(
                    "Post-quantum indication",
                    data["postquantum"].as_str().unwrap_or("unknown").into()
                ),
                info_row(
                    "Encoding",
                    if data["armor"].as_bool() == Some(true) {
                        "ASCII armor"
                    } else {
                        "Binary"
                    }
                    .into()
                ),
                info_row(
                    "Header",
                    format_size(sizes["header"].as_u64().unwrap_or_default())
                ),
                info_row(
                    "Encryption overhead",
                    format_size(sizes["overhead"].as_u64().unwrap_or_default())
                ),
                info_row(
                    "Payload (if valid)",
                    format_size(sizes["min_payload"].as_u64().unwrap_or_default())
                )
            ]
            .spacing(15);
            body=body.push(card().title("Encryption details").content(list).footer(row![button("Copy JSON").icon(lucide::COPY).on_press(Message::CopyInspection),button("Save JSON").icon(lucide::SAVE).variant(shad::button::Variant::Outline).on_press(Message::Pick(Pick::InspectSave))].spacing(8))).push(alert("Metadata is not authentication").icon(lucide::INFO).description("This information comes from the unverified header. Only successful decryption verifies the file's authenticity and completeness."));
        }
        body.into()
    }
    fn settings_view(&self) -> Element<'_, Message> {
        let renderer = select(Some(self.next_renderer.clone()), Message::Renderer)
            .option("auto".into(), "Automatic · GPU with CPU fallback")
            .option("cpu".into(), "CPU · quickest startup")
            .option("gpu".into(), "GPU · hardware renderer")
            .width(Length::Fill)
            .disabled(self.blocked());
        column![heading("A few useful controls.","Your engine, plugins, and native rendering preferences."),
            card().title("Official age engine").description(self.engine_info.clone()).content(muted("The Rust interface starts a local engine only for an operation. Passphrases and PINs use private pipes; they are never command-line arguments.",13)).footer(button("Check engine version").icon(lucide::CIRCLE_CHECK).variant(shad::button::Variant::Outline).disabled(self.blocked()).on_press(Message::CheckEngine)),
            card().title("Plugins & hardware tokens").description("Install the appropriate age plugin, then select its folder if it is not on PATH.").content(muted(self.plugin_dir.as_ref().map(|p|p.display().to_string()).unwrap_or_else(||"Bundled plugins and the system PATH".into()),12)).content(muted("Use a plugin recipient/identity in Encrypt or Decrypt, or enter its name for the CLI's -j option. Choosing an encrypted file by itself never launches a plugin.",13)).footer(button("Choose plugin folder").icon(lucide::FOLDER_OPEN).variant(shad::button::Variant::Outline).disabled(self.blocked()).on_press(Message::Pick(Pick::PluginDir))),
            card().title("Graphics").description(if self.graphics_info.is_empty(){"Native Iced rendering".into()}else{self.graphics_info.clone()}).content(renderer).content(muted("Restart opens a fresh session in the selected mode. Your current file list and unsaved text are not carried over.",12)).footer(button("Restart in selected mode").icon(lucide::ROTATE_CW).variant(shad::button::Variant::Outline).disabled(self.blocked()).on_press(Message::Restart)),
        ].spacing(22).into()
    }
    fn guide_view(&self) -> Element<'_, Message> {
        column![heading("Powerful, without a terminal.","The age command-line workflows, translated into native controls."),
            card().title("Choose how the file key is protected").content(muted("Classic uses X25519. Post-quantum uses hybrid ML-KEM-768 + X25519. Passphrase uses scrypt. SSH uses Ed25519 or RSA public keys, and plugins support their own recipients and hardware devices. All use age's fixed ChaCha20-Poly1305 payload encryption. There is no AES/cipher switch in age.",14)),
            card().title("Add recipients from several sources").content(muted("Paste public keys (-r), import recipient files (-R), or expand Use my identities / plugins to encrypt to your own identity files (-e -i) or a named plugin (-j). One recipient per line; blank lines and # comments are accepted. Each recipient can decrypt independently. Age rejects incompatible mixtures such as classic and post-quantum recipients.",14)),
            card().title("Unlock with the right identity").content(muted("Add multiple native or SSH identity files (-i), including passphrase-protected keys. You can also paste an identity from the clipboard; it stays hidden. File passphrases are detected automatically. Plugin PINs and confirmations appear in dialogs. SSH keys accessed only through ssh-agent are not supported by age.",14)),
            card().title("Files, text, and output control").content(muted("Files handles binary data and streams large files. Text & clipboard is the GUI equivalent of standard input/output; encrypted text is automatically armored. Choose a folder for a batch, or Save as for one filename (-o). ASCII armor is -a. Existing outputs are preserved unless you enable replacement and confirm the paths. Input files remain protected.",14)),
            card().title("Keys and inspection").content(muted("Your keys creates classic or post-quantum identities (age-keygen -pq), optionally protected with a passphrase, and exports recipients (age-keygen -y). Inspect displays the official age-inspect metadata and exports JSON. Inspection is not an authenticity check; decryption is.",14)),
            self.reassurance(),
        ].spacing(20).into()
    }
}

fn heading<'a>(title: &'a str, description: &'a str) -> Element<'a, Message> {
    column![
        text(title).size(29).font(font::semibold()),
        muted(description, 14)
    ]
    .spacing(7)
    .into()
}
fn editor<'a>(
    content: &'a shad::textarea::Content,
    placeholder: &'a str,
    height: u32,
    disabled: bool,
    on_action: fn(shad::textarea::Action) -> Message,
) -> Element<'a, Message> {
    let input = widget::text_editor(content)
        .placeholder(placeholder)
        .height(height)
        .size(12)
        .font(font::mono())
        .padding([9, 11])
        .wrapping(text::Wrapping::WordOrGlyph)
        .style(|theme, status| shad::textarea::style(theme, status, false));
    if disabled {
        input.into()
    } else {
        input.on_action(on_action).into()
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
fn nav<'a>(label: &'a str, icon: shad::Icon, page: Page, app: &App) -> Element<'a, Message> {
    shad::button::Button::new(
        row![icon.sized(16), text(label).size(14).font(font::medium())]
            .spacing(10)
            .width(Length::Fill),
    )
    .size(shad::button::Size::Lg)
    .width(Length::Fill)
    .variant(if page == app.page {
        shad::button::Variant::Secondary
    } else {
        shad::button::Variant::Ghost
    })
    .disabled(app.blocked())
    .on_press(Message::Navigate(page))
    .into()
}
fn remove_button(
    kind: Pick,
    index: usize,
    disabled: bool,
) -> shad::button::Button<'static, Message> {
    icon_button(lucide::X)
        .size(shad::button::Size::IconSm)
        .variant(shad::button::Variant::Ghost)
        .disabled(disabled)
        .on_press(Message::Remove(kind, index))
}
fn path_list(paths: &[PathBuf], kind: Pick, disabled: bool) -> Element<'_, Message> {
    let mut list = column![].spacing(6);
    for (i, p) in paths.iter().enumerate() {
        list = list.push(
            row![
                lucide::FILE_KEY.sized(14),
                muted(filename(p), 12).width(Length::Fill),
                remove_button(kind, i, disabled)
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );
    }
    list.into()
}
fn info_row(label: &str, value: String) -> Element<'_, Message> {
    row![
        muted(label, 12).width(210),
        text(value)
            .size(13)
            .wrapping(text::Wrapping::WordOrGlyph)
            .width(Length::Fill)
    ]
    .spacing(20)
    .into()
}
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
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
fn soft_style(t: &Theme) -> container::Style {
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
fn outline_style(t: &Theme) -> container::Style {
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
