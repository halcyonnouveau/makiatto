# Introduction

Makiatto builds a global CDN that routes users to their nearest server for fast content delivery. By deploying a single binary to servers in different geographic regions, you create a self-organising mesh network that handles geographic DNS routing, automatic SSL certificates, and content synchronisation without external infrastructure.

## How It Works

Each Makiatto node runs a single Rust binary containing an embedded DNS server, WireGuard mesh, distributed SQLite database, and web servers. When you deploy a new node with `makiatto-cli machine init`, it auto-discovers existing peers, joins the WireGuard mesh, replicates state, and begins serving traffic.

Nodes detect their own coordinates during initialisation. When users query your domain, the DNS server calculates the geographically closest node and returns that IP address. Nodes continue serving content from local state even during network partitions between peers.

## Key Capabilities

Beyond static content delivery, Makiatto supports:

- **[Dynamic image processing](./usage-guide.html#dynamic-image-processing)**: On-the-fly image resizing, format conversion, and optimisation with query parameters
- **[WebAssembly functions](./usage-guide/wasm.html)**: Deploy edge functions as HTTP handlers and file transformers that run on all CDN nodes

## When to Use Makiatto

Makiatto is not a cost-effective alternative to services like Cloudflare or Fastly. Running multiple VMs globally will cost significantly more than using a commercial CDN. However, Makiatto makes sense when you want:

- **Self-sovereignty**: You want full control over your infrastructure without third parties seeing your traffic or contributing to internet centralisation
- **Censorship resistance**: You're serving legal material that CDNs might block (adult material, political speech, etc.)
- **Experimentation**: You enjoy building and running your own infrastructure

If none of these apply and cost is a primary concern, a commercial CDN is likely a better choice.

Ready to get started? Head to the [Getting Started](./getting-started.md) guide to install Makiatto and set up your first CDN node.
