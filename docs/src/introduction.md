# Introduction

Makiatto builds a global CDN by deploying a single Rust binary to servers in different regions. Each node contains an embedded DNS server, WireGuard mesh, and distributed database with automatic SSL certificates and content synchronisation.

Deploy new nodes with `makiatto-cli machine init`. Each node detects its coordinates, auto-discovers existing peers through the distributed database, joins the WireGuard mesh, and replicates state. When users query your domain, the DNS server calculates the geographically closest node and returns that IP address. Because nodes operate independently with local state, they continue serving content even during network partitions between peers.

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
