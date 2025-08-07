# Installation

There are several ways to install the Makiatto CLI on your local machine.

## Using Cargo

If you have Rust installed, you can install directly from crates.io:

```bash
cargo install makiatto-cli
```

If you don't have Rust installed, get it from [rustup.rs](https://rustup.rs/).

## Download from GitHub Releases

You can download pre-built binaries from the [releases page](https://github.com/halcyonnouveau/makiatto/releases).

```admonish important
Download the `makiatto-cli-*` files, not the `makiatto-*` files (those are the daemon binaries for servers).
```

Choose the correct file for your platform:
- `makiatto-cli-x86_64-unknown-linux-gnu.tar.gz` - Linux (Intel/AMD)
- `makiatto-cli-aarch64-unknown-linux-gnu.tar.gz` - Linux (ARM64)
- `makiatto-cli-x86_64-apple-darwin.tar.gz` - macOS (Intel)
- `makiatto-cli-aarch64-apple-darwin.tar.gz` - macOS (Apple Silicon)

Then extract and install:
```bash
tar -xzf makiatto-cli-*.tar.gz
chmod +x makiatto-cli
mv makiatto-cli /usr/local/bin/
```

## Verify installation

After installation, verify everything is working:

```bash
makiatto-cli --version
```
