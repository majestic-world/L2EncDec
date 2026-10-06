.PHONY: build

# Optimized build tuned for runtime speed (see [profile.release] in Cargo.toml).
# Output: target/release/L2Enc.exe
build:
	cargo build --release
