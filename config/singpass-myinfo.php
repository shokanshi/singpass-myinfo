<?php

use Shokanshi\SingpassMyInfo\Http\Controllers\GetAuthenticationController;
use Shokanshi\SingpassMyInfo\Http\Controllers\GetCallbackController;
use Shokanshi\SingpassMyInfo\Http\Controllers\GetJwksController;

return [
    'client_id' => env('SINGPASS_CLIENT_ID'),
    'redirect' => env('SINGPASS_REDIRECT_URI'),
    'signing_key_passphrase' => env('SINGPASS_SIGNING_PRIVATE_KEY_PASSPHRASE', ''),
    'signing_key_file' => env('SINGPASS_SIGNING_PRIVATE_KEY_FILE'),

    // used by socialite. leave it empty since Singpass uses client assertion
    'client_secret' => '',

    'decryption_key_passphrase' => env('SINGPASS_DECRYPTION_PRIVATE_KEY_PASSPHRASE', ''),
    'decryption_key_file' => env('SINGPASS_DECRYPTION_PRIVATE_KEY_FILE'),

    'domain' => env('SINGPASS_DOMAIN'),
    'well_known_configuration_url' => env('SINGPASS_DISCOVERY_ENDPOINT'),

    'scopes' => env('SINGPASS_SCOPES', 'openid uinfin name sex race dob birthcountry passportnumber passtype passstatus passexpirydate mobileno email regadd'),

    // this is the route that will be used to redirect to Singpass login page
    'authentication_endpoint_url' => env('SINGPASS_AUTHENTICATION_URL', 'sp/login'),
    'authentication_endpoint_controller' => GetAuthenticationController::class,

    // this is the route that will be called when Singpass redirects back after authentication
    'callback_endpoint_url' => env('SINGPASS_CALLBACK_URL', 'sp/callback'),
    'callback_endpoint_controller' => GetCallbackController::class,

    // this is the url that Singpass will call to retrieve your public jwks for signing and encryption
    'jwks_endpoint_url' => env('SINGPASS_JWKS_URL', 'sp/jwks'),
    'jwks_endpoint_controller' => GetJwksController::class,
];
