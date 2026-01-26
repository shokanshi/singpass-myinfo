# Changelog

All notable changes to `singpass-myinfo` will be documented in this file.

## v2.0.0 - 2026-01-26

### What's Changed

* FAPI 2.0 Full Support for Singpass v5 by @shokanshi in https://github.com/shokanshi/singpass-myinfo/pull/16

**Full Changelog**: https://github.com/shokanshi/singpass-myinfo/compare/v1.1.1...v2.0.0

## v1.1.1 - 2026-01-24

Add exception handling:

1. handle redirectUrl is missing error for getAuthUrl()
2. handle jwe error in getMyInfoJWE()

## v1.1.0 - 2025-11-08

To avoid confusion from `SINGPASS_REDIRECT_URI` and `SINGPASS_CALLBACK_ENDPOINT` in `.env` file. The provider now will automatically set `redirectUrl` based on `route('singpass.callback')`.

This behavior can always be overwritten by calling `setRedirectUrl()`.

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