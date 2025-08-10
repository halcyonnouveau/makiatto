# How to contribute to Makiatto

#### **Did you find a bug?**

* **Do not open up a GitHub issue if the bug is a security vulnerability in Makiatto**, and instead refer to our [security policy](https://github.com/halcyonnouveau/makiatto/security/policy).

* **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/halcyonnouveau/makiatto/issues).

* If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/halcyonnouveau/makiatto/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behaviour that is not occurring.

* If possible, provide the relevant information for your issue:
  * Your operating system and version
  * Makiatto daemon version (`makiatto --version`)
  * Makiatto CLI version (`makiatto-cli --version`)
  * If building from source: Your Rust version (`rustc --version`)
  * For daemon issues: Relevant logs (`journalctl -u makiatto` or equivalent)
  * The full error message with backtrace

#### **Did you write a patch that fixes a bug?**

* Open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.

* Before submitting, please ensure:
  * You have added tests for your fix
  * All relevant tests pass (see Testing section below)
  * Code is formatted (`cargo fmt --all`)
  * No clippy warnings (`cargo clippy --all-targets --all-features`)

#### **Did you fix whitespace, format code, or make a purely cosmetic patch?**

Changes that are cosmetic in nature and do not add anything substantial to the stability, functionality, or testability of Makiatto will generally not be accepted. Please focus on meaningful improvements.

#### **Do you intend to add a new feature or change an existing one?**

* First, check if the feature has already been discussed in [Issues](https://github.com/halcyonnouveau/makiatto/issues).

* Open a new issue describing your proposed feature and start a discussion.

* Do not start working on the feature until you have collected positive feedback about the change.

* For significant changes, consider:
  * How it affects existing users
  * Performance implications
  * Documentation needs
  * Backwards compatibility

#### **Do you have questions about the source code?**

* Check the [README](README.md) and existing documentation first.

* For questions about using Makiatto, please open a [Discussion](https://github.com/halcyonnouveau/makiatto/discussions).

#### **Do you want to contribute to the Makiatto documentation?**

* Documentation improvements are always welcome! This includes:
  * Fixing typos or clarifying existing docs
  * Adding examples
  * Improving API documentation
  * Writing tutorials or guides

* For small changes, feel free to submit a PR directly.

* For larger documentation efforts, please open an issue first to discuss the scope.

#### **Development Setup**

1. Ensure you have Rust installed via [rustup](https://rustup.rs/)
   * The project uses Rust nightly (configured via `rust-toolchain.toml`)
   * Rustup will automatically download and use the correct version
2. Clone the repository: `git clone https://github.com/halcyonnouveau/makiatto.git`
3. Build the project: `cargo build`

#### **Testing**

**Unit Tests:**
```bash
# Run unit tests only
cargo test --workspace --exclude integration-tests

# Important: Do NOT use `cargo test --all` as it includes integration tests
```

**Integration Tests:**

Docker or Podman is **required** for running integration tests. The tests use containers to create isolated test environments for Makiatto's distributed features including content synchronisation, GeoDNS routing, HTTP(S) servers, etc.

We recommend using `cargo-nextest` for better output and retry capabilities:

```bash
# Install cargo-nextest if you haven't already
cargo install cargo-nextest

# Run integration tests with retries
cargo nextest run --retries 3 --package integration-tests --features docker-build
```

The `docker-build` feature flag builds fresh Docker images from the current source code before running tests. Use this when you've made changes to the Makiatto daemon. It will not rebuild if no changes have been made, so it's safe to always use.

#### **Coding Standards**

* Follow Rust naming conventions and idioms
* Use `cargo fmt --all` to format all workspace code
* Address all `cargo clippy --all-targets --all-features` warnings
* Write tests for new functionality
* Keep commits focused and atomic
* Write clear, descriptive commit messages
