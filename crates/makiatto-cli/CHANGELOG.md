# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.3](https://github.com/halcyonnouveau/makiatto/compare/v0.5.2...v0.5.3) - 2026-01-12

### Fixed

- docs change

## [0.5.2](https://github.com/halcyonnouveau/makiatto/compare/v0.5.1...v0.5.2) - 2026-01-12

### Added

- add DNS resolution for WireGuard peers and machine restart command

## [0.5.1](https://github.com/halcyonnouveau/makiatto/compare/v0.5.0...v0.5.1) - 2026-01-11

### Added

- add external peer support and observability auto-discovery

## [0.5.0](https://github.com/halcyonnouveau/makiatto/compare/v0.4.4...v0.5.0) - 2025-12-02

### Changed

- [**breaking**] rename makiatto-cli binary to maki

## [0.4.2](https://github.com/halcyonnouveau/makiatto/compare/v0.4.1...v0.4.2) - 2025-11-12

### Added

- add dns failovers

### Other

- i love to update my docs
- update readme and docs again but fr this time
- update readme and docs

## [0.4.1](https://github.com/halcyonnouveau/makiatto/compare/v0.4.0...v0.4.1) - 2025-11-06

### Fixed

- wit downloading

## [0.4.0](https://github.com/halcyonnouveau/makiatto/compare/v0.3.4...v0.4.0) - 2025-11-06

### Added

- [**breaking**] wasm runtime ([#68](https://github.com/halcyonnouveau/makiatto/pull/68))

## [0.3.4](https://github.com/halcyonnouveau/makiatto/compare/v0.3.3...v0.3.4) - 2025-11-03

### Added

- add dynamic image processing

## [0.3.3](https://github.com/halcyonnouveau/makiatto/compare/v0.3.2...v0.3.3) - 2025-10-22

### Added

- health check verifies all dns records

## [0.3.2](https://github.com/halcyonnouveau/makiatto/compare/v0.3.1...v0.3.2) - 2025-08-12

### Added

- adjust compression and add basic benching tool

## [0.3.1](https://github.com/halcyonnouveau/makiatto/compare/v0.3.0...v0.3.1) - 2025-08-10

### Added

- add `MAKIATTO_PROFILE` env var for profile path
- add warning if daemon out of date
- exit upgrading if a node failed

## [0.3.0](https://github.com/halcyonnouveau/makiatto/compare/v0.2.3...v0.3.0) - 2025-08-09

### Added

- add machine remove command
- add version command
- cluster health command
- [**breaking**] move ssh port to separate option

### Other

- remove warning
- add book contents

## [0.2.3](https://github.com/halcyonnouveau/makiatto/compare/v0.2.2...v0.2.3) - 2025-08-03

### Added

- update printlns

## [0.2.2](https://github.com/halcyonnouveau/makiatto/compare/v0.2.1...v0.2.2) - 2025-08-03

### Fixed

- cleanup deps

## [0.2.1](https://github.com/halcyonnouveau/makiatto/compare/v0.2.0...v0.2.1) - 2025-08-03

## [0.2.0](https://github.com/halcyonnouveau/makiatto/compare/v0.1.0...v0.2.0) - 2025-08-03

### Added

- add nameserver guide command

## [0.1.0](https://github.com/halcyonnouveau/makiatto/compare/v0.0.3...v0.1.0) - 2025-08-03

### Added

- fixes from testing in prod

## [0.0.2](https://github.com/halcyonnouveau/makiatto/compare/makiatto-cli-v0.0.1...makiatto-cli-v0.0.2) - 2025-08-01

### Added

- able to specify sync target
- sync command
- file system sync
- cname support in axum server
- certificate renewals
- validate node name
- add web server cache and metrics
- add https server
- add web server
- add `machine add` command
- add corrosion subscription watcher and dns tests
- improve DNS server graceful shutdown and provision automation
- add port constants and improve SSH container detection
- add wireguard peer management and container support
- add corrosion tests
- add process for second node init

### Fixed

- fix provision
- integration tests/use Arc<T>
- dont publish makiatto-cli lib

### Other

- rsync fix

## [0.0.1](https://github.com/halcyonnouveau/makiatto/releases/tag/makiatto-cli-v0.0.1) - 2025-07-09

### Other

- initial commit
