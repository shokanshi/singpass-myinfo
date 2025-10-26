# Laravel Socialite For Singpass MyInfo v5

[![Latest Version on Packagist](https://img.shields.io/packagist/v/shokanshi/singpass-myinfo.svg?style=flat-square)](https://packagist.org/packages/shokanshi/singpass-myinfo)
[![Total Downloads](https://img.shields.io/packagist/dt/shokanshi/singpass-myinfo.svg?style=flat-square)](https://packagist.org/packages/shokanshi/singpass-myinfo)

This is a Laravel socialite package for Singpass MyInfo v5. The purpose of this package is to make it very easy for PHP developers to integrate Singpass v5.

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
SINGPASS_REDIRECT_URI=https://your-company.com/sp/callback

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
SINGPASS_AUTHENTICATION_ENDPOINT_=sp/login
SINGPASS_CALLBACK_ENDPOINT_=sp/callback
SINGPASS_JWKS_ENDPOINT_=sp/jwks
```

## Checking If It Work Right Out Of The Box For You

Assuming you are using the default setup and filled up the values in `.env` file:

1. Test your jwks endpoint to see if Singpass is able to access it:

```
https://your-company.com/sp/jwks
```

2. Test if it redirects to Singpass auth endpoint:

```
https://your-company.com/sp/login
```

# Configuration

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

    // if the setting defined in callback_endpoint_url is: sp/callback
    // the callback url will be: https://your-company.com/sp/callback
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
SINGPASS_AUTHENTICATION_URL=sp/login
SINGPASS_CALLBACK_URL=sp/callback
SINGPASS_JWKS_URL=sp/jwks
```

Accessing routes via name in your Laravel codes:

```php
route('singpass.login');
route('singpass.callback');
route('singpass.jwks');
```

### Custom Routes

If you prefer the authentication url to be `https://your-company.com/sp/auth`, you can update `SINGPASS_AUTHENTICATION_URL` to `sp/auth`:

```ini
SINGPASS_AUTHENTICATION_URL=sp/auth
```

# Custom Controllers

You can customize the default controller via the `singpass-myinfo.php` config file.

```php
'authentication_endpoint_controller' => GetAuthenticationController::class,
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
'authentication_endpoint_controller' => MySingpassAuthController::class,
```

In `MySingpassAuthController.php`:

```php
class MySingpassAuthController extends Controller
{
    public function __invoke(Request $request)
    {
        Socialite::driver('singpass')
        ->when(app()->environment('local'), function($singpass) {
            $singpass
                ->setClientId('staging client id')
                ->setOpenIdDiscoveryUrl('https://stg-id.singpass.gov.sg/.well-known/openid-configuration')
                ->setRedirectUrl(route('singpass.login'))
                ->setSigningPrivateKeys([
                    [
                        'keyContent' => 'staging private key 1',
                        'passphrase' => 'staging password 1'
                    ]
                ])
                ->setDecryptionPrivateKeys([
                    [
                        'keyContent' => 'staging private key 2',
                        'passphrase' => 'staging password 2'
                    ]
                ]);
        })
        ->when(app()->environment('production'), function($singpass) {
            $singpass
                ->setClientId('production client id')
                ->setOpenIdDiscoveryUrl('https://id.singpass.gov.sg/.well-known/openid-configuration')
                ->setRedirectUrl(route('singpass.login'))
                ->setSigningPrivateKeys([
                    [
                        'keyContent' => 'production private key 1',
                        'passphrase' => 'production password 1'
                    ]
                ])
                ->setDecryptionPrivateKeys([
                    [
                        'keyContent' => 'production private key 2',
                        'passphrase' => 'production password 2'
                    ]
                ]);
        })
        ->redirect();
    }
}
```

**ℹ️ Note:**

1. For the above example, the same customization has to be applied to `callback_endpoint_controller` and `jwks_endpoint_controller` since the endpoint is now based on environment of the application.
2. The above is just an example to illustrate how you may customize the controllers.

## Methods Available

If you have a multitenancy application and would like to allow onboarding of individual tenant onto Singpass, the following methods will be useful to you. You can setup custom controllers (like the [example](#example) above) to handle the aspect of multitenancy with them.

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

Overwrite the value of `SINGPASS_REDIRECT_URI` defined in the `.env` file when called.

#### Parameters

| Name           | Type     | Description                | Default    |
| -------------- | -------- | -------------------------- | ---------- |
| `$redirectUrl` | `string` | Singpass callback endpoint | _required_ |

---

### `setSigningPrivateKeys(array $keys): self`

Assign a set of private keys to the collection and overwrite the value of `SINGPASS_SIGNING_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name    | Type    | Description                                                                                                                                                      | Default    |
| ------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `$keys` | `array` | Private keys that will be used for signing in the following format: `[['keyContent' => 'pem file content here', 'passphrase' => 'secret password here'], [...]]` | _required_ |

---

### `setDecryptionPrivateKeys(array $keys): self`

Assign a set of private keys to the collection and overwrite the value of `SINGPASS_DECRYPTION_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name    | Type    | Description                                                                                                                                                      | Default    |
| ------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `$keys` | `array` | Private keys that will be used for signing in the following format: `[['keyContent' => 'pem file content here', 'passphrase' => 'secret password here'], [...]]` | _required_ |

---

### `addSigningPrivateKey(array $key): self`

Add a new private key to the collection and overwrite the value of `SINGPASS_SIGNING_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name   | Type    | Description                                                                                                                                            | Default    |
| ------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `$key` | `array` | Private key that will be used for signing in the following format: `['keyContent' => 'pem file content here', 'passphrase' => 'secret password here']` | _required_ |

---

### `addDecryptionPrivateKey(array $key): self`

Add a new private key to the collection and overwrite the value of `SINGPASS_DECRYPTION_PRIVATE_KEY_FILE` defined in the `.env` file when called.

#### Parameters

| Name   | Type    | Description                                                                                                                                               | Default    |
| ------ | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `$key` | `array` | Private key that will be used for decryption in the following format: `['keyContent' => 'pem file content here', 'passphrase' => 'secret password here']` | _required_ |

---

### `generateJwksForSingpassPortal(): string`

Return a json encoded string of the jwks that Singpass will call and retrieve.

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

        $singpass = Socialite::driver('singpass');

        $singpass
            ->setClientId($tenant->singpass_client_id)
            ->setOpenIdDiscoveryUrl($tenant->singpass_openid_discovery_endpoint)
            ->setScopes([$tenant->singpass_scopes])
            ->setRedirectUrl(route('singpass.login'));

        foreach ($tenant->singpassPrivateKeys() as $key) {
            $singpass
                ->when(Carbon::now()->between($key->valid_from, $key->valid_to), function($singpass) use ($key) {
                    $singpass->when($key->type === 'signing', function($singpass) use ($key) {
                        $singpass->addSigningPrivateKey([
                            'keyContent' => $key->key_content,
                            'passphrase' => $key->passphrase,
                        ]);
                    })->when($key->type === 'decryption', function($singpass) use ($key) {
                        $singpass->addDecryptionPrivateKey([
                            'keyContent' => $key->key_content,
                            'passphrase' => $key->passphrase,
                        ]);
                    });
                });
        }

        return response()->json(json_encode($singpass->generateJwksForSingpassPortal()));
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

The code of this package is heavily influenced by the code shown in [Laravel Socialite](https://leeliwei930.medium.com/integrating-singpass-login-api-with-laravel-socialite-provider-part-1-onboarding-setup-210d7fa0f31f).

You will also find some code reference from [Accredifysg/SingPass-Login](https://github.com/Accredifysg/SingPass-Login/) in this package.

-   [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
