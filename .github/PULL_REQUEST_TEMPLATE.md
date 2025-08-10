<!-- Add your description of the PR here -->
<!-- You can link an issue to be auto-closed when this is merged by writing 'Closes #1234' or 'Fixes #1234' -->

### How has this been tested?
<!-- Please describe in detail how you tested your changes. N/A if it is a docs change -->

### The following has been done
<!-- Mark each item as done by replace the space in '[ ]' with an 'x', e.g. '[x]' -->

- [ ] PR title is prefixed with `feat:`, `fix:`, `chore:`, or `docs:`
- [ ] The message body above clearly illustrates what problems it solves
- [ ] Tests added/updated for the changes (if applicable)

### Tests and linting

- [ ] Formatting has been run with `cargo fmt --all`
- [ ] Clippy passes with `cargo clippy --all-targets --all-features`
- [ ] Unit tests pass with `cargo test --workspace --exclude integration-tests`
- [ ] Integration tests pass with `cargo nextest run --retries 3 --package integration-tests --features docker-build`
