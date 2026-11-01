# Rust GUI and graphics selection

Research checked 1 November 2026 against project documentation, published crate manifests, and downloaded source.

The two hard requirements are a native Rust implementation and a genuine CPU rendering path, with hardware acceleration when available. A shadcn visual vocabulary should not require embedding a browser.

| Candidate | Evidence and fit | Decision |
|---|---|---|
| **Iced + shadcn-iced** | Iced explicitly supplies `iced_wgpu` and `iced_tiny_skia`. The former supports Vulkan, Metal, and DX12; the latter is a software fallback. shadcn-iced 0.3.0 directly supports Iced 0.14 with bundled fonts, Lucide icons, semantic theme tokens, and keyboard-focus primitives. | Selected. Pin exact UI versions and commit Cargo.lock. |
| **Slint** | Offers a lightweight software renderer and several accelerated renderers. The software renderer has documented limitations, including some shadows, clipping, and text features. Its declarative UI language is distinct from Rust code. | A credible alternative for especially small embedded/desktop interfaces, but Iced provides the direct Rust/shadcn combination requested here. |
| **GPUI Kit** | Provides a substantial native Rust component system and advertises GPU-accelerated interfaces, with behavior and component layers analogous to shadcn. | Strong UI option; the reviewed documentation did not establish the independent CPU fallback required here. |

There is no claim that Iced is universally fastest. Startup, idle behavior, layout, and the actual adapter need measurement in the built application. shadcn-iced is a young dependency; its exact version is pinned and the application is validated against that version.

Primary sources:

- [Iced repository and renderer design](https://github.com/iced-rs/iced)
- [Iced 0.14.0 features](https://docs.rs/crate/iced/0.14.0/features)
- [shadcn-iced 0.3.0](https://docs.rs/crate/shadcn-iced/0.3.0)
- [shadcn-iced source](https://github.com/r4ai/shadcn-iced)
- [Slint backends and renderers](https://docs.slint.dev/latest/docs/slint/guide/backends-and-renderers/backends_and_renderers/)
- [GPUI Kit](https://github.com/longbridge/gpui-kit)
- [age reference implementation](https://github.com/FiloSottile/age)
- [Rust age library](https://docs.rs/age/0.11.5/age/)

Version 0.1 used the Rust age library directly. Version 0.2 keeps the UI and file/process orchestration in Rust and uses a lazy local adapter around the official Go age 1.3.2 library for full current recipient and plugin compatibility. The engine never starts on an ordinary empty GUI launch. See cli-parity.md for the supported workflows.
