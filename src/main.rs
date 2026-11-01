#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod ui;

use shadcn_iced::ApplicationExt;
use std::{path::PathBuf, time::Instant};

#[derive(Clone)]
pub struct Options {
    pub started: Instant,
    pub renderer: String,
    pub probe: Option<PathBuf>,
    pub files: Vec<PathBuf>,
    pub dark: bool,
    pub page: String,
}

fn main() -> iced::Result {
    let started = Instant::now();
    let mut options = Options {
        started,
        renderer: "auto".into(),
        probe: None,
        files: Vec::new(),
        dark: false,
        page: "encrypt".into(),
    };
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--renderer") => {
                options.renderer = args
                    .next()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            }
            Some("--probe") => options.probe = args.next().map(PathBuf::from),
            Some("--dark") => options.dark = true,
            Some("--page") => {
                options.page = args
                    .next()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            }
            Some("--decrypt" | "-d") => options.page = "decrypt".into(),
            Some("--encrypt" | "-e") => options.page = "encrypt".into(),
            Some("--") => {
                options.files.extend(args.map(PathBuf::from));
                break;
            }
            _ => options.files.push(PathBuf::from(argument)),
        }
    }
    // Set the renderer before Iced, Tokio, or any worker threads exist. This
    // single-threaded startup is the safety requirement of set_var in Rust 2024.
    match options.renderer.as_str() {
        "cpu" => unsafe { std::env::set_var("ICED_BACKEND", "tiny-skia") },
        "gpu" => unsafe { std::env::set_var("ICED_BACKEND", "wgpu") },
        "auto" => {}
        _ => {
            eprintln!("Use --renderer auto, cpu, or gpu.");
            std::process::exit(2);
        }
    }
    iced::application(
        move || ui::App::boot(options.clone()),
        ui::App::update,
        ui::App::view,
    )
    .title(concat!(
        "age — file encryption · ",
        env!("CARGO_PKG_VERSION")
    ))
    .theme(ui::App::theme)
    .subscription(ui::App::subscription)
    .window(iced::window::Settings {
        size: iced::Size::new(1160.0, 800.0),
        min_size: Some(iced::Size::new(940.0, 680.0)),
        exit_on_close_request: false,
        ..Default::default()
    })
    .centered()
    .shadcn_iced()
    .run()
}
