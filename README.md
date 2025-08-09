<img src="https://raw.githubusercontent.com/halcyonnouveau/makiatto/refs/heads/main/docs/assets/mochaccino.png" alt="mochaccino" style="max-width: 100%;">

# Makiatto

[![status](https://github.com/halcyonnouveau/makiatto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/halcyonnouveau/makiatto/actions/workflows/ci.yml)
[![crate](https://img.shields.io/crates/v/makiatto-cli.svg)](https://crates.io/crates/makiatto-cli)
[![docs](https://img.shields.io/badge/book-latest-blue?logo=mdbook)](https://halcyonnouveau.github.io/makiatto/)
![license](https://img.shields.io/badge/License-APACHE--2.0%2FMIT-blue)

Makiatto is a lightweight CDN that lets you deploy and distribute content across multiple servers with minimal infrastructure overhead. It creates a secure WireGuard mesh network between your machines and provides automatic content synchronisation, GeoDNS routing, and coordinate-based geographic distribution through simple CLI commands.

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

## Quick Start

1. **Install the CLI**

   ```bash
   cargo install makiatto-cli
   ```

2. **Create your CDN nodes**

   Set up nodes in different geographic regions. Each node will automatically join the mesh network and sync content. We recommend using at least 3 nodes as you'll need a minimum of 3 nameservers for proper DNS redundancy.

   ```bash
   makiatto-cli machine init <name> <user>@<ip address>
   makiatto-cli machine init vector root@203.0.113.1
   makiatto-cli machine init klukai ubuntu@2001:db8::1
   ```

3. **Configure your project**

   Create a `makiatto.toml` file in your project to define your domain and content paths.

   ```toml
   [[domain]]
   name = "zuccherocat.cafe"
   path = "./dist"
   ```

4. **Deploy your content**

   Sync your static files and domain config to all nodes in the mesh.

   ```bash
   makiatto-cli sync
   ```

5. **Configure your domain nameservers**

   Set up your domain to use Makiatto's custom nameservers for GeoDNS routing. Follow the guide to add glue records and configure your domain registrar.

   ```bash
   makiatto-cli dns nameserver-setup
   ```

Your content should now be distributed globally with automatic geolocation DNS routing! For more detailed instructions, see the [documentation](https://halcyonnouveau.github.io/makiatto/).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
