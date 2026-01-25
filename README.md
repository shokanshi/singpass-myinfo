# Laravel Socialite Provider For Singpass MyInfo v5 (FAPI 2.0)

[![Latest Version on Packagist](https://img.shields.io/packagist/v/shokanshi/singpass-myinfo.svg?style=flat-square)](https://packagist.org/packages/shokanshi/singpass-myinfo)
[![Total Downloads](https://img.shields.io/packagist/dt/shokanshi/singpass-myinfo.svg?style=flat-square)](https://packagist.org/packages/shokanshi/singpass-myinfo)
[![PHP Version](https://img.shields.io/packagist/php-v/shokanshi/singpass-myinfo)](https://packagist.org/packages/shokanshi/singpass-myinfo)

The purpose of this Laravel package is to make it very easy for PHP (8.3+) developers to integrate [Singpass MyInfo v5](https://docs.developer.singpass.gov.sg/docs/products/myinfo/introduction).

[FAPI 2.0](https://docs.developer.singpass.gov.sg/docs/upcoming-changes/fapi-2.0-authentication-api) support is now available. To use Singpass v5 without FAPI 2.0, please use [v1.1.1](https://github.com/shokanshi/singpass-myinfo/releases/tag/v1.1.1).

**ℹ️ Note:** All APIs must be FAPI 2.0 compliant by 31 Dec 2026.

## Requirements

- PHP ≥ 8.3
- Laravel ≥ 11.0

## Support Me

A sponsor will be greatly appreciated but not required to use this package. 😊

## Installation

You can install the package via composer:

```bash
composer require shokanshi/singpass-myinfo
```

## Setting Up Private Keys

The package will attempt to load the private keys from `storage/app`.

**❌ DO NOT** store the private keys in `./storage/app/public` folder! They will be publicly accessible!

If you have not already done so, create a `secure` folder within `storage/app` in your project folder.

Create private key for signing:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ./storage/app/secure/your-singpass-signing-private.pem
```

Create private key for decryption:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ./storage/app/secure/your-singpass-decryption-private.pem
```

Add the following variables to your `.env` file and adjust accordingly to your app. The following is just an example.

```ini
# Singpass variables
SINGPASS_CLIENT_ID=

# Base folder is ./storage/app
SINGPASS_SIGNING_PRIVATE_KEY_FILE=secure/your-singpass-signing-private.pem
SINGPASS_SIGNING_PRIVATE_KEY_PASSPHRASE=

# Base folder is ./storage/app
SINGPASS_DECRYPTION_PRIVATE_KEY_FILE=secure/your-singpass-decryption-private.pem
SINGPASS_DECRYPTION_PRIVATE_KEY_PASSPHRASE=

SINGPASS_OPENID_DISCOVERY_ENDPOINT=https://stg-id.singpass.gov.sg/.well-known/openid-configuration

# for Singpass login, set openid as the only scope. Additional scopes (space separated within double quotes) will switch to MyInfo flow
SINGPASS_SCOPES="openid"

# Default routes
SINGPASS_AUTHORIZATION_ENDPOINT=sp/login
SINGPASS_CALLBACK_ENDPOINT=sp/callback
SINGPASS_JWKS_ENDPOINT=sp/jwks
```

## Checking If It Work Right Out Of The Box For You

Remember to create your [Singpass application](https://docs.developer.singpass.gov.sg/docs/getting-started/create-singpass-application) at [Singpass Developer Portal](https://developer.singpass.gov.sg/) before you proceed to test.

Assuming you are using the default setup and filled up the values in `.env` file:

1. Test your jwks endpoint to see if Singpass is able to access it:

```
https://your-company.com/sp/jwks
```

2. Test if it redirects to Singpass auth endpoint:

```
https://your-company.com/sp/login
```

## Configuration

You can publish the config file with:

```bash
php artisan vendor:publish --tag="singpass-myinfo-config"
```

This is the content of the published config file:

```php
return [
    // default to Singpass staging
    'openid_discovery_endpoint' => env('SINGPASS_OPENID_DISCOVERY_ENDPOINT', 'https://stg-id.singpass.gov.sg/.well-known/openid-configuration'),

    'client_id' => env('SINGPASS_CLIENT_ID'),

    // this setting is here because socialite requires it to be defined. SingpassProvider will always overwrite it to route('singpass.callback')
    'redirect' => env('SINGPASS_REDIRECT_URI'),

    // the private key file that your application will be used for signing
    'signing_private_key_passphrase' => env('SINGPASS_SIGNING_PRIVATE_KEY_PASSPHRASE', ''),
    'signing_private_key_file' => env('SINGPASS_SIGNING_PRIVATE_KEY_FILE'),

    // the private key file that your application will be used for decryption
    'decryption_private_key_passphrase' => env('SINGPASS_DECRYPTION_PRIVATE_KEY_PASSPHRASE', ''),
    'decryption_private_key_file' => env('SINGPASS_DECRYPTION_PRIVATE_KEY_FILE'),

    // used by socialite. leave it empty since Singpass uses client assertion
    'client_secret' => '',

    // default to Singpass login if SINGPASS_SCOPES is blank. for MyInfo, define additional scopes that are space separated
    // e.g. "openid uinfin name sex race dob birthcountry passportnumber"
    'scopes' => env('SINGPASS_SCOPES', 'openid'),

    // this is the route that will be used to redirect to Singpass login page
    // you can customize this in .env file
    'authorization_endpoint' => env('SINGPASS_AUTHORIZATION_ENDPOINT', 'sp/login'),

    // the controller that will handle the redirection to Singpass login page
    // to customize, you can replace it with your own controller in this config file
    'authorization_endpoint_controller' => GetAuthorizationController::class,

    // this is the route that will be called when Singpass redirects back after authentication
    // you can customize this in .env file
    'callback_endpoint' => env('SINGPASS_CALLBACK_ENDPOINT', 'sp/callback'),

    // the controller that will handle the callback from Singpass after login
    // to customize, you can replace it with your own controller in this config file
    'callback_endpoint_controller' => GetCallbackController::class,

    // this is the url that Singpass will call to retrieve your public jwks for signing and encryption
    // you can customize this in .env file
    'jwks_endpoint' => env('SINGPASS_JWKS_ENDPOINT', 'sp/jwks'),

    // the controller that Singpass portal will use to retrieve your application jwks
    // typically you won't want to change it unless you want to implement key rotation logic
    'jwks_endpoint_controller' => GetJwksController::class,
];
```

## Routes

There are three default routes that you can customize, namely:

```ini
SINGPASS_AUTHORIZATION_ENDPOINT=sp/login
SINGPASS_CALLBACK_ENDPOINT=sp/callback
SINGPASS_JWKS_ENDPOINT=sp/jwks
```

You can access the routes via name in your Laravel codes:

```php
route('singpass.login');
route('singpass.callback');
route('singpass.jwks');
```

### Custom Routes

If you prefer the authentication url to be `https://your-company.com/sp/auth`, you can update `SINGPASS_AUTHORIZATION_URL` to `sp/auth`:

```ini
SINGPASS_AUTHORIZATION_URL=sp/auth
```

## Custom Controllers

You can customize the default controller via the `singpass-myinfo.php` config file.

```php
'authorization_endpoint_controller' => GetAuthorizationController::class,
'callback_endpoint_controller' => GetCallbackController::class,
'jwks_endpoint_controller' => GetJwksController::class,
```

### Example:

To create an authentication controller that will switch between local and production environment

```bash
php artisan make:controller MySingpassAuthController
```

In `singpass-myinfo.php` config file:

```php
'authorization_endpoint_controller' => MySingpassAuthController::class,
```

In `MySingpassAuthController.php`:

```php
class MySingpassAuthController extends Controller
{
    public function __invoke(Request $request)
    {
        return singpass()
        ->when(app()->environment('local'), function($singpass) {
            $singpass
                ->setClientId('staging client id')
                ->setOpenIdDiscoveryUrl('https://stg-id.singpass.gov.sg/.well-known/openid-configuration')
                ->addSigningKey(Storage::disk('local')->get('stage_signing_key_1.pem'))
                ->addDecryptionKey(Storage::disk('local')->get('stage_decryption_key_1.pem'));
        })
        ->when(app()->environment('production'), function($singpass) {
            $singpass
                ->setClientId('production client id')
                ->setOpenIdDiscoveryUrl('https://id.singpass.gov.sg/.well-known/openid-configuration')
                ->addSigningKey(Storage::disk('local')->get('prod_signing_key_1.pem'))
                ->addDecryptionKey(Storage::disk('local')->get('prod_decryption_key_1.pem'));
        })
        ->redirect();
    }
}
```

**ℹ️ Note:**

1. For the above example, the same customization has to be applied to `callback_endpoint_controller` and `jwks_endpoint_controller` since the endpoint is now based on environment of the application.
2. The above is just an example to illustrate how you may customize the controllers.

## Using the Socialite Provider

### `singpass(): SingpassProvider`

A helper method that return the SingpassProvider Socialite object.

In the event where `singpass()` is not available (likely in conflict with another helper method in your project), you can still access the Socialite by calling `Socialite::driver('singpass')`.

---

### `user(): \Laravel\Socialite\Contracts\User`

Return the Socialite user object.

## Methods Available

If you have a multitenancy application and would like to allow onboarding of individual tenant onto Singpass, the following methods will be useful to you. You can setup custom controllers (like the [example](#example) above) to handle the aspect of multitenancy with them.

---

### `redirect(): \Illuminate\Http\RedirectResponse`

Redirect the user of the application to the provider's authentication screen.

To retrieve the redirect url, you can call `singpass()->redirect()->getTargetUrl()`.

---

### `setClientId(string $clientId): self`

Overwrite the value of `SINGPASS_CLIENT_ID` defined in the `.env` file when called.

#### Parameters

| Name        | Type     | Description        | Default    |
| ----------- | -------- | ------------------ | ---------- |
| `$clientId` | `string` | Singpass client id | _required_ |

---

### `setOpenIdDiscoveryUrl(string $url): self`

Overwrite the value of `SINGPASS_DISCOVERY_ENDPOINT` defined in the `.env` file when called.

#### Parameters

| Name   | Type     | Description                        | Default    |
| ------ | -------- | ---------------------------------- | ---------- |
| `$url` | `string` | Singpass openid discovery endpoint | _required_ |

---

### `setRedirectUrl(string $redirectUrl): self`

Overwrite the value of `SINGPASS_REDIRECT_URI` defined in the `.env` file when called. Useful when your application have different redirects based on certain business logic.

#### Parameters

| Name           | Type     | Description                | Default    |
| -------------- | -------- | -------------------------- | ---------- |
| `$redirectUrl` | `string` | Singpass callback endpoint | _required_ |

---

### `addSigningKey(string $keyContent, ?string $passphrase): self`

Add a new private key to the collection and overwrite the value of `SINGPASS_SIGNING_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name          | Type     | Description                                                           | Default    |
| ------------- | -------- | --------------------------------------------------------------------- | ---------- |
| `$keyContent` | `string` | The content of the private key pem file that will be used for signing | _required_ |
| `$passphrase` | `string` | The passphrase for the pem file if it is encrypted                    |            |

---

### `addSigningKeyFromJsonObject(string $json): self`

Add a new private key to the collection and overwrite the value of `SINGPASS_SIGNING_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name    | Type     | Description                                                          | Default    |
| ------- | -------- | -------------------------------------------------------------------- | ---------- |
| `$json` | `string` | Json encoded string of the private JWK that will be used for signing | _required_ |

#### Sample json object from [Singpass Demo](https://github.com/singpass/demo-app) for signing:

```json
{
    "alg": "ES256",
    "kty": "EC",
    "x": "tqG7PiAPD0xTBKdxDd4t8xAjJleP3Szw1CZiBjogmoc",
    "y": "256TjvubWV-x-C8lptl7eSbMa7pQUXH9LY1AIHUGINk",
    "crv": "P-256",
    "d": "PgL1UKVpvg_GeKdxV-oUEPIDhGBP2YYZLGiZ5HXDZDI",
    "use": "sig",
    "kid": "my-sig-key"
}
```

---

### `addDecryptionKey(string $keyContent, ?string $passphrase): self`

Add a new private key to the collection and overwrite the value of `SINGPASS_DECRYPTION_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name          | Type     | Description                                                              | Default    |
| ------------- | -------- | ------------------------------------------------------------------------ | ---------- |
| `$keyContent` | `string` | The content of the private key pem file that will be used for decryption | _required_ |
| `$passphrase` | `string` | The passphrase for the pem file if it is encrypted                       |            |

---

### `addDecryptionKeyFromJsonObject(string $json): self`

Add a new private key to the collection and overwrite the value of `SINGPASS_DECRYPTION_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name    | Type     | Description                                                             | Default    |
| ------- | -------- | ----------------------------------------------------------------------- | ---------- |
| `$json` | `string` | Json encoded string of the private JWK that will be used for decryption | _required_ |

#### Sample json object from [Singpass Demo](https://github.com/singpass/demo-app) for decryption:

```json
{
    "alg": "ECDH-ES+A256KW",
    "kty": "EC",
    "x": "_TSrfW3arG1Ebc8pCyT-r5lAFvCh_rJvC5HD5-y8yvs",
    "y": "Sr2vpuU6gzdUiXddGnRJIroXCfdameaR1mgU49H5h9A",
    "crv": "P-256",
    "d": "AEabUwi3VjOOfiyoOtSGrqpl8cfhcUhNtj-xh1l-UYE",
    "use": "enc",
    "kid": "my-enc-key"
}
```

---

### `generateJwksForSingpassPortal(): array`

Return an array of public keys that will be json encoded and consumed by Singpass.

---

### `when($value, ?callable $callback = null, ?callable $default = null): self`

The `when()` method allows you to conditionally execute a closure (a function) if a given condition evaluates to true. Its primary purpose is to apply modifications to an object within a method chain, based on a dynamic condition, without having to break the chain into a traditional if statement.

In short: It's an if statement that you can use inside a method chain. See the [Example](#example) above.

#### Parameters

| Name        | Type       | Description                                                              | Default    |
| ----------- | ---------- | ------------------------------------------------------------------------ | ---------- |
| `$value`    | `boolean`  | Apply the callback if the given "value" is (or resolves to) truthy       | _required_ |
| `$callback` | `callable` | The callback when $value resolved to true                                |            |
| `$default`  | `callable` | The callback when $value resolved to false and this parameter is defined |            |

## Advanced Usage Example (Multitenancy + Key Rotation)

Singpass recommends [key rotation](https://docs.developer.singpass.gov.sg/docs/upcoming-changes/fapi-2.0-authentication-api/technical-concepts/json-web-key-sets-jwks) on a yearly basis.

The following is an example to illustrate a more advance use case for this package that handles multitenancy and key rotation.

[Spatie multitenancy](https://github.com/spatie/laravel-multitenancy) package will be used for illustration.

### Custom fields added to Tenant table

| Name                                 | Type           | Description                           | Default    |
| ------------------------------------ | -------------- | ------------------------------------- | ---------- |
| `singpass_client_id`                 | `varchar(255)` | Singpass client id                    | _required_ |
| `singpass_openid_discovery_endpoint` | `varchar(255)` | Singpass openid discovery endpoint id | _required_ |
| `singpass_scopes`                    | `text`         | Space separated Singpass scopes       | `openid`   |

### New Table: tenant_private_keys

| Name          | Type           | Description                          | Default    |
| ------------- | -------------- | ------------------------------------ | ---------- |
| `id`          | `bigint`       | Primary key                          | _required_ |
| `tenant_id`   | `bigint`       | Foreign key                          | _required_ |
| `provider`    | `varchar(50)`  | e.g. singpass                        | _required_ |
| `type`        | `varchar(50)`  | e.g. signing or decryption           | _required_ |
| `key_content` | `text`         | Encrypted pem file content           | _required_ |
| `passphrase`  | `varchar(255)` | Encrypted passphrase for signing key | _required_ |
| `valid_from`  | `datetime`     | The date the key is valid from       | _required_ |
| `valid_to`    | `datetime`     | The date the key is valid to         | _required_ |

```php
class MySingpassJwksEndpointController extends Controller
{
    public function __invoke(Request $request)
    {
        $tenant = Tenant::current();

        singpass()
            ->setClientId($tenant->singpass_client_id)
            ->setOpenIdDiscoveryUrl($tenant->singpass_openid_discovery_endpoint)
            ->setScopes([$tenant->singpass_scopes]);

        foreach ($tenant->singpassPrivateKeys() as $key) {
            singpass()
                ->when(Carbon::now()->between($key->valid_from, $key->valid_to), function($singpass) use ($key) {
                    $singpass
                        ->when($key->type === 'signing', function($singpass) use ($key) {
                            $singpass->addSigningKey($key->key_content, $key->passphrase);
                        })
                        ->when($key->type === 'decryption', function($singpass) use ($key) {
                            $singpass->addDecryptionKey($key->key_content, $key->passphrase);
                        });
                });
        }

        return response()->json(json_encode(singpass()->generateJwksForSingpassPortal()));
    }
}
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

The code of this package is heavily influenced by the code shown in [Laravel Socialite - Singpass](https://leeliwei930.medium.com/integrating-singpass-login-api-with-laravel-socialite-provider-part-1-onboarding-setup-210d7fa0f31f).

You will also find some code reference from [Accredifysg/SingPass-Login](https://github.com/Accredifysg/SingPass-Login/) in this package.

- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
