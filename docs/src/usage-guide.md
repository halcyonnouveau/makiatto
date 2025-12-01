# Usage Guide

This guide covers the core commands and workflows for managing your Makiatto CDN.

## Machine Management

List all configured machines in your profile:

```bash
maki machine list
```

Add an existing Makiatto node to your profile:

```bash
maki machine add <user@host>
```

Upgrade Makiatto binary on machines:

```bash
maki machine upgrade [machine names...]
```

If no machine names are provided, all machines will be upgraded. You can optionally specify `--binary-path` to use a local binary instead of downloading from GitHub releases.

Remove a machine from the cluster:

```bash
maki machine remove <machine-name>
```

This command will:
- Remove the machine from all peer databases in the cluster
- Stop and disable the makiatto service on the target machine
- Clean up all makiatto files and directories (`/var/makiatto`, `/etc/makiatto`)
- Remove the makiatto binary and user
- Update your profile configuration

You'll be prompted for confirmation before removal. Use `--force` to skip the confirmation prompt:

```bash
maki machine remove <machine-name> --force
```

```admonish warning
Machine removal is permanent and cannot be undone. The machine will need to be re-initialised with `machine init` to rejoin the cluster.
```

## Status

Check cluster health:

```bash
maki health
```

The health command performs comprehensive checks across your entire cluster.

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

Your machine configuration is stored in a profile (default: `~/.config/makiatto/default.toml`). Profiles can be stored anywhere - in your home directory for personal use or in your project repository for team sharing:

```bash
# Personal profile in home directory
maki --profile ~/.config/makiatto/zucchero.toml machine list

# Shared profile in project repo
maki --profile ./deployment/zucchero.toml sync
```

```admonish info
Profiles contain only public configuration data (machine names, SSH targets, WireGuard public keys, IP addresses). Private keys and credentials are never stored in profiles - SSH keys are passed separately via the `--ssh-priv-key` flag (if needed). This makes profiles safe to commit to version control for team collaboration.
```

You can also set the `MAKIATTO_PROFILE` environment variable:

```bash
export MAKIATTO_PROFILE=./deployment/defy.toml
maki sync
```

The `--profile` flag takes precedence over the environment variable when both are set.

## Dynamic Image Processing

Makiatto includes built-in dynamic image processing powered by [Imageflow](https://github.com/imazen/imageflow). Transform images on-the-fly by adding query parameters to your image URLs:

```
https://zuccherocat.cafe/photos/springfield.jpg?w=800&fmt=webp&q=85
```

### Available Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `w` | integer | Width in pixels | `?w=800` |
| `h` | integer | Height in pixels | `?h=600` |
| `fit` | string | Fit mode: `max`, `pad`, `crop`, `stretch` | `?fit=crop` |
| `fmt` | string | Output format: `webp`, `jpg`, `png` | `?fmt=webp` |
| `q` | integer | Quality (1-100) | `?q=85` |

**Fit modes:** `max` (default, shrink only), `pad` (letterbox), `crop` (fill), `stretch` (distort)

**Caching:** Processed images are cached in memory (500MB LRU by default) and automatically invalidated when source files change. Images without query parameters are served as static files with no processing overhead.
