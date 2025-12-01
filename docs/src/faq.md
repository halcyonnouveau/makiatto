# FAQ

## What operating systems does Makiatto support?

Makiatto only works on Linux. The daemon relies on Linux-specific features for WireGuard, networking, and system integration. You can run the CLI (`maki`) from macOS or Linux to manage your Linux nodes remotely, but the actual CDN nodes must be running Linux servers. Windows binaries for the CLI are not currently available but may be added in the future.

## Why does Makiatto use GeoDNS instead of anycast?

Commercial CDN providers use anycast routing where the same IP address is announced from multiple locations, and internet routing protocols direct users to the nearest server. While this is elegant, it requires:
- Owning IP address blocks (expensive and requires justification)
- BGP peering agreements with multiple ISPs
- Infrastructure in internet exchange points
- Significant technical expertise and relationships

GeoDNS achieves similar results by using GPS coordinates to determine which server is closest to each user. This approach works with regular VPS providers and doesn't require any special infrastructure, making it perfect for self-hosters and small teams who want CDN functionality without enterprise-level requirements.

## How many nodes do I need?

Minimum 3 nodes for proper DNS redundancy (you need at least 3 nameservers). For meaningful geographic distribution, you'd want nodes in different regions (e.g., North America, Europe, Asia). You can start with 1 node for testing, but DNS redundancy requires 3+.

## Can I use Makiatto with an existing web server?

Currently, Makiatto includes its own web server that listens on ports 80 and 443. It's designed to be the primary web server for your domains.

If you have an existing web server (like nginx or Apache) on the same machine, you would need to:
- Run your existing server on different ports (e.g., 8080/8443), or
- Use dedicated machines for Makiatto (recommended)

Future versions may support reverse proxy configurations, but for now Makiatto expects to own ports 80/443.

## Can I host dynamic content or is it only for static files?

Makiatto is primarily designed for static content distribution, but also includes WebAssembly support for dynamic functionality:

**Static content:**
- Files are synced from your local `path` directory to all nodes and served directly
- Perfect for websites, documentation, images, and assets

**Dynamic content with WebAssembly:**
- **Edge functions**: Deploy HTTP handlers that run on all CDN nodes (similar to Cloudflare Workers)
- **File transformers**: Process files on-the-fly before serving them (like minification, compression, or adding headers)

See the [WebAssembly Functions](./usage-guide/wasm.md) guide for details on creating and deploying WASM components.

For traditional server-side applications (databases, WebSockets, long-running processes), you may still want to use Makiatto for static assets while keeping your backend on a separate domain and infrastructure.

## Can I mix different hosting providers?

Yes! Since nodes communicate via WireGuard mesh over the public internet, you can mix any providers (AWS, DigitalOcean, Hetzner, Vultr, bare metal servers, etc.) as long as they have public IP addresses and allow WireGuard traffic.
