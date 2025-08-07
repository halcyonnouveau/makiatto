# FAQ

## Why does Makiatto use GeoDNS instead of anycast?

Commercial CDN providers use anycast routing where the same IP address is announced from multiple locations, and internet routing protocols direct users to the nearest server. While this is elegant, it requires:
- Owning IP address blocks (expensive and requires justification)
- BGP peering agreements with multiple ISPs
- Infrastructure in internet exchange points
- Significant technical expertise and relationships

GeoDNS achieves similar results by using GPS coordinates to determine which server is closest to each user. This approach works with regular VPS providers and doesn't require any special infrastructure, making it perfect for self-hosters and small teams who want CDN functionality without enterprise-level requirements.

## Can I use Makiatto with an existing web server?

Currently, Makiatto includes its own web server that listens on ports 80 and 443. It's designed to be the primary web server for your domains.

If you have an existing web server (like nginx or Apache) on the same machine, you would need to:
- Run your existing server on different ports (e.g., 8080/8443), or
- Use dedicated machines for Makiatto (recommended)

Future versions may support reverse proxy configurations, but for now Makiatto expects to own ports 80/443.

## Can I host dynamic content or is it only for static files?

Makiatto is currently designed for static content distribution. It syncs files from your local `path` directory to all nodes and serves them directly.

For dynamic content, you have a few options today:
- Use Makiatto for your static assets (JS, CSS, images) while keeping your dynamic app on a separate domain
- Use static site generators to pre-build your dynamic content into static files

However, WebAssembly support is planned for the future! This will allow you to:
- Transform content on-the-fly with WebAssembly filters (similar to nginx filter modules)
- Deploy serverless functions like Cloudflare Workers
- Build dynamic applications that run on all your CDN nodes

Until then, the focus on static content is what keeps Makiatto simple and efficient - there's no need to worry about session state, database replication, or cache invalidation across nodes.
