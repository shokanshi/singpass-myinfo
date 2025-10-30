# Changelog

All notable changes to `singpass-myinfo` will be documented in this file.

## v1.0.0 Initial stable release - 2025-10-30

### v1.0.0 - 30 Oct 2023

#### Highlights

- Socialite provider for SingPass / MyInfo authorisation code flow
- PKCE support built-in
- Configurable sandbox / production endpoints

#### Added

- `SingpassProvider` – Socialite driver
- `SingpassMyInfoServiceProvider` – auto-discovery package provider
- `config/singpass-myinfo.php` – publishable config file

#### Installation

```bash
composer require shokanshi/singpass-myinfo

```