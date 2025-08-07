# Introduction

Makiatto is a lightweight, self-hosted CDN (Content Delivery Network) that lets you deploy and distribute content across multiple servers with minimal infrastructure overhead.

It creates a secure WireGuard mesh network between your machines and provides automatic content synchronisation across all nodes, GeoDNS routing to direct users to their nearest server, coordinate-based geographic distribution through simple CLI commands, and built-in SSL certificate management via Let's Encrypt.

Makiatto is simple - one-command deployment with no complex configurations or control planes. Just run `makiatto-cli machine init` to add a node and `makiatto-cli sync` to deploy content. It's decentralised with no single point of failure - each node operates independently while staying in sync through a distributed consensus mechanism. And it's completely self-hosted, giving you full control over your infrastructure with no vendor lock-in, no surprise bills, and no data leaving your servers.

Ready to get started? Head to the [Getting Started](./getting-started.md) guide to install Makiatto and set up your first CDN node.
