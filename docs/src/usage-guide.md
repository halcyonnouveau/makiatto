# Usage Guide

This guide covers the core commands and workflows for managing your Makiatto CDN.

## Machine Management

List all configured machines in your profile:

```bash
makiatto-cli machine list
```

Add an existing Makiatto node to your profile:

```bash
makiatto-cli machine add <user@host>
```

Upgrade Makiatto binary on machines:

```bash
makiatto-cli machine upgrade [machine names...]
```

If no machine names are provided, all machines will be upgraded. You can optionally specify `--binary-path` to use a local binary instead of downloading from GitHub releases.

## Status

Check cluster status:

```bash
makiatto-cli status
```

```admonish note
The status command is currently being implemented and will show detailed information about your cluster in future releases.
```


## Configuration

Your project configuration lives in `makiatto.toml`. Here's a complete example:

```toml
[[domain]]
name = "example.com"
path = "./dist"
aliases = ["www.example.com", "old-domain.com"]

[[domain.records]]
type = "TXT"
name = "_dmarc"  # Creates _dmarc.example.com
value = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

[[domain.records]]
type = "MX"
name = "@"  # @ means the root domain (example.com)
value = "mail.example.com"
ttl = 300
priority = 10
```

### Required fields

- `name` - The domain name to serve
- `path` - Path to static files (relative to makiatto.toml)

### Optional fields

**`aliases`** - Domains that CNAME to your site. When external domains point to your Makiatto domain via CNAME, listing them here tells Makiatto to:
- Obtain SSL certificates for them
- Serve your content when visitors access them
- Common uses: www subdomains, alternative domain names

**`domain.records`** - Custom DNS records to add. Useful for:
- Email configuration (MX, SPF, DKIM)
- Domain verification (TXT)
- Subdomains pointing elsewhere
- Custom records beyond what Makiatto auto-creates

### Automatic DNS records

Makiatto automatically creates:
- A/AAAA records for your domain (with GeoDNS)
- NS records for your nameservers
- SOA record for the zone
- CAA record for Let's Encrypt

### Multiple domains

You can configure multiple domains in one file:

```toml
[[domain]]
name = "example.com"
path = "./dist/blog"

[[domain]]
name = "zuccherocat.cafe"
path = "./dist/site"
```

```admonish note
Each domain must be a root domain that you control at the registrar level. Subdomains like `blog.example.com` should be handled via DNS records, not as separate domains.
```

## Profile Management

Your machine configuration is stored in a profile (default: `~/.config/makiatto/default.toml`). You can use different profiles for different environments:

```bash
makiatto-cli --profile ~/.config/makiatto/prod.toml machine list
```

The profile stores:
- Machine names and SSH targets
- WireGuard public keys and addresses
- Geographic coordinates (latitude/longitude)
- IPv4/IPv6 addresses
- Nameserver role assignments
