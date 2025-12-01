<img src="https://raw.githubusercontent.com/halcyonnouveau/makiatto/refs/heads/main/docs/assets/mochaccino.png" alt="mochaccino" style="max-width: 100%;">

# Makiatto

[![status](https://github.com/halcyonnouveau/makiatto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/halcyonnouveau/makiatto/actions/workflows/ci.yml)
[![crate](https://img.shields.io/crates/v/makiatto-cli.svg)](https://crates.io/crates/makiatto-cli)
[![docs](https://img.shields.io/badge/book-latest-blue?logo=mdbook)](https://halcyonnouveau.github.io/makiatto/)
![license](https://img.shields.io/badge/License-APACHE--2.0%2FMIT-blue)

Makiatto builds a global CDN that routes users to their nearest server for fast content delivery. Deploy one binary per Linux server and they self-organise into a mesh network with geographic DNS routing, automatic SSL certificates, and content synchronisation. Scale out by adding nodes without needing external load balancers, orchestration, or management infrastructure.

## Features

- **Vertically integrated in Rust**: Single binary with embedded DNS server, WireGuard mesh, and distributed database with no external infrastructure required
- **Self-organising nodes**: Deploy with one command. Nodes auto-discover peers, detect their coordinates, and coordinate GeoDNS routing
- **Fault tolerance**: Unhealthy nodes are automatically excluded from routing with failover to healthy nodes
- **Shared-nothing architecture**: Each node operates independently with no central coordination required
- **[Dynamic image processing](https://halcyonnouveau.github.io/makiatto/usage-guide.html#dynamic-image-processing)**: On-the-fly image resizing, format conversion, and optimisation with query parameters
- **[WebAssembly functions](https://halcyonnouveau.github.io/makiatto/usage-guide/wasm.html)**: Deploy edge functions as HTTP handlers and file transformers that run on all CDN nodes

## Quick Start

1. **Install the CLI**

   ```bash
   cargo install makiatto-cli
   ```

2. **Create your CDN nodes**

   Set up nodes in different geographic regions. Each node will automatically join the mesh network and sync content. We recommend using at least 3 nodes as you'll need a minimum of 3 nameservers for proper DNS redundancy.

   ```bash
   maki machine init <name> <user>@<ip address>
   maki machine init vector root@203.0.113.1
   maki machine init klukai ubuntu@2001:db8::1
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
   maki sync
   ```

5. **Configure your domain nameservers**

   Set up your domain to use Makiatto's custom nameservers for GeoDNS routing. Follow the guide to add glue records and configure your domain registrar.

   ```bash
   maki dns nameserver-setup
   ```

Your content should now be distributed globally with automatic geolocation DNS routing! For more detailed instructions, see the [documentation](https://halcyonnouveau.github.io/makiatto/).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
