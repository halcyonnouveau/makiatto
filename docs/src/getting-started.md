# Getting Started

This guide will walk you through setting up your first CDN nodes with Makiatto.

## Prerequisites

You'll need servers to run your CDN nodes. These can be VPS instances, dedicated servers, or cloud VMs. Each server should have:
- A public IPv4 address (IPv6 is recommended but optional)
- A supported Linux distribution (Ubuntu, Debian, or similar)
- SSH access (any port)
- These ports open:
  - 53 (DNS)
  - 80 (HTTP)
  - 443 (HTTPS)
  - 853 (DNS over TLS)
  - 51820 (WireGuard)

```admonish tip
We recommend at least 3 servers in different geographic locations. You need 3+ nameservers for proper DNS redundancy, and geographic distribution is the whole point of a CDN! But you can start with just one server to test things out.
```

Make sure you have the Makiatto CLI installed on your local machine. See the [Installation](./introduction/installation.md) guide if you haven't done this yet.

## Setting up your first nodes

Initialise your CDN nodes with the `machine init` command. This will install the Makiatto daemon on each server and configure them to join the mesh network:

```bash
makiatto-cli machine init vector root@203.0.113.1
makiatto-cli machine init klukai ubuntu@198.51.100.1
makiatto-cli machine init tololo admin@192.0.2.1
```

The command format is `makiatto-cli machine init <name> <user>@<ip>`. These names will be used as nameserver hostnames (e.g., `vector.ns.example.com`), so choose something short and meaningful.

You can verify your nodes are connected:

```bash
makiatto-cli machine list
```

## Creating your project configuration

Create a `makiatto.toml` file in your project directory:

```toml
[[domain]]
name = "example.com"
path = "./dist"
```

This tells Makiatto which domain to serve and where your static files are located. The `path` is relative to the `makiatto.toml` file.

```admonish important
You must use a root domain that you own and control at the registrar level (like `example.com`), not a subdomain (like `blog.example.com`). Makiatto needs to be the authoritative nameserver for the entire domain to handle DNS and SSL certificates properly.
```

## Deploying content

With your nodes set up and configuration ready, deploy your content:

```bash
makiatto-cli sync
```

This command syncs your static files and domain configuration to all nodes in the mesh. Your content is now distributed globally!

## DNS setup

For GeoDNS routing to work, you need to configure your domain to use Makiatto's nameservers:

```bash
makiatto-cli dns nameserver-setup
```

This command will output detailed instructions like this:

```
Follow these steps to configure your custom nameservers:

:: Step 1: Add glue records to your domain registrar

Glue records tell the internet where to find your nameservers when they're subdomains of your own domain.
Without them, there's a circular dependency: DNS can't find your nameservers to resolve your domain.
Add these as glue records (also called 'name server records' or 'host records') in your domain registrar's control panel.

:: Glue records for example.com:

  vector.ns.example.com: 203.0.113.1, 2001:db8::1
  klukai.ns.example.com: 198.51.100.1, 2001:db8::2
  tololo.ns.example.com: 192.0.2.1, 2001:db8::3

:: Step 2: Set your domain to use your custom nameservers

After adding glue records, you must also tell your registrar to use your custom nameservers instead of their defaults.
In your domain registrar's control panel, change the nameservers for your domain to:

:: Nameservers for example.com:

  vector.ns.example.com
  klukai.ns.example.com
  tololo.ns.example.com

:: Step 3: Testing and verification
After configuration, test your setup with:

  dig @vector.ns.example.com example.com

Note: DNS changes may take 24-48 hours to propagate globally.
```

Once DNS propagates, visitors will be automatically routed to their nearest node.

## What's next?

Your CDN is now operational! Check out the [Usage Guide](./usage-guide.md) for more advanced features like managing multiple domains, updating content, and monitoring your nodes.
