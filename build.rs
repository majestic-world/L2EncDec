//! Embeds the Windows version resource described in
//! `[package.metadata.winresource]` of Cargo.toml, plus the application icon.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .compile()
            .expect("failed to compile the Windows version resource");
    }
}
