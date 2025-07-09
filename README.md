<img src="https://raw.githubusercontent.com/halcyonnouveau/makiatto/refs/heads/main/docs/assets/mochaccino.png" alt="mochaccino" style="max-width: 100%;">

# Makiatto

[![status](https://github.com/halcyonnouveau/makiatto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/halcyonnouveau/makiatto/actions/workflows/ci.yml)
[![crate](https://img.shields.io/crates/v/makiatto-cli.svg)](https://crates.io/crates/makiatto-cli)
[![docs](https://img.shields.io/badge/book-latest-blue?logo=mdbook)](https://halcyonnouveau.github.io/makiatto/)
![license](https://img.shields.io/badge/License-APACHE--2.0%2FMIT-blue)

Makiatto is a lightweight CDN that lets you deploy and distribute content across multiple servers with minimal infrastructure overhead. It creates a secure WireGuard mesh network between your machines and provides automatic content synchronisation, GeoDNS routing, and coordinate-based geographic distribution through simple CLI commands.

> [!NOTE]
> Makiatto is currently under active development and not all features have been implemented. Do not use this yet.

## Features

- **One-command deployment**: Initialise nodes with a single CLI command
- **GeoDNS with coordinate-based routing**: Automatically direct users to their nearest server
- **No single point of failure**: Decentralised architecture with no control plane
- **Automatic SSL certificates**: Built-in Let's Encrypt integration
- **Simple content management**: Easy file uploads and website deployments

## Who is this for?

- **Developers** who want their own CDN infrastructure instead of using commercial providers
- **Privacy-conscious users** who prefer self-hosted solutions
- **Small teams** serving static sites that need global performance without vendor lock-in
- **Hobbyists** who enjoy building their own infrastructure
- **Anyone** with multiple VPS instances who wants to put them to good use

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
