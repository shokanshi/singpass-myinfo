<?php

use Shokanshi\SingpassMyInfo\Http\Controllers\GetAuthenticationController;
use Shokanshi\SingpassMyInfo\Http\Controllers\GetCallbackController;
use Shokanshi\SingpassMyInfo\Http\Controllers\GetJwksController;

return [
    'client_id' => env('SINGPASS_CLIENT_ID'),
    'redirect' => env('SINGPASS_REDIRECT_URI'),

    // the private key file that your application will be used for signing and decryption
    'client_private_key_passphrase' => env('SINGPASS_CLIENT_PRIVATE_KEY_PASSPHRASE', ''),
    'client_private_key_file' => env('SINGPASS_CLIENT_PRIVATE_KEY_FILE'),

    // used by socialite. leave it empty since Singpass uses client assertion
    'client_secret' => '',

    'domain' => env('SINGPASS_DOMAIN'),
    'openid_discovery_url' => env('SINGPASS_DISCOVERY_ENDPOINT'),

    'scopes' => env('SINGPASS_SCOPES', 'openid uinfin name'),

    // this is the route that will be used to redirect to Singpass login page
    // you can customize this in .env file
    'authentication_endpoint_url' => env('SINGPASS_AUTHENTICATION_URL', 'sp/login'),

    // the controller that will handle the redirection to Singpass login page
    // to customize, you can replace it with your own controller in this config file
    'authentication_endpoint_controller' => GetAuthenticationController::class,

    // this is the route that will be called when Singpass redirects back after authentication
    // you can customize this in .env file
    'callback_endpoint_url' => env('SINGPASS_CALLBACK_URL', 'sp/callback'),

    // the controller that will handle the callback from Singpass after login
    // to customize, you can replace it with your own controller in this config file
    'callback_endpoint_controller' => GetCallbackController::class,

    // this is the url that Singpass will call to retrieve your public jwks for signing and encryption
    // you can customize this in .env file
    'jwks_endpoint_url' => env('SINGPASS_JWKS_URL', 'sp/jwks'),

    // the controller that Singpass portal will use to retrieve your application jwks
    // typically you won't want to change it
    'jwks_endpoint_controller' => GetJwksController::class,
];
