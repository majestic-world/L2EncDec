//! Embeds the Windows version resource described in
//! `[package.metadata.winresource]` of Cargo.toml.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .compile()
            .expect("failed to compile the Windows version resource");
    }
}
