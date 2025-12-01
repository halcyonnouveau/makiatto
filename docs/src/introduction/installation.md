# Installation

There are several ways to install the Makiatto CLI on your local machine.

## Using Cargo

If you have Rust installed, you can install directly from crates.io:

```bash
cargo install makiatto-cli  # installs as `maki`
```

If you don't have Rust installed, get it from [rustup.rs](https://rustup.rs/).

## Download from GitHub Releases

You can download pre-built binaries from the [releases page](https://github.com/halcyonnouveau/makiatto/releases).

```admonish important
Download the `maki-*` files, not the `makiatto-*` files (those are the daemon binaries for servers).
```

Choose the correct file for your platform:
- `maki-x86_64-unknown-linux-gnu.tar.gz` - Linux (Intel/AMD)
- `maki-aarch64-unknown-linux-gnu.tar.gz` - Linux (ARM64)
- `maki-x86_64-apple-darwin.tar.gz` - macOS (Intel)
- `maki-aarch64-apple-darwin.tar.gz` - macOS (Apple Silicon)

Then extract and install:
```bash
tar -xzf maki-*.tar.gz
chmod +x maki
mv maki /usr/local/bin/
```

## Verify installation

After installation, verify everything is working:

```bash
maki --version
```
