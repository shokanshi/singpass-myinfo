<?php

use Shokanshi\SingpassMyInfo\Http\Controllers\GetAuthorizationController;
use Shokanshi\SingpassMyInfo\Http\Controllers\GetCallbackController;
use Shokanshi\SingpassMyInfo\Http\Controllers\GetJwksController;

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
