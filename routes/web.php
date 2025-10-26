<?php

use Illuminate\Support\Facades\Route;

Route::middleware('web')->group(function () {
    // this is the route that will be used to redirect to Singpass login page
    Route::get(
        config('singpass-myinfo.authorization_endpoint'),
        config('singpass-myinfo.authorization_endpoint_controller')
    )->name('singpass.login');

    // this is the route that will be called when Singpass redirects back after authentication
    Route::get(
        config('singpass-myinfo.callback_endpoint'),
        config('singpass-myinfo.callback_endpoint_controller')
    )->name('singpass.callback');

    // this is the url that Singpass will call to retrieve your public jwks for signing and encryption
    Route::get(
        config('singpass-myinfo.jwks_endpoint'),
        config('singpass-myinfo.jwks_endpoint_controller')
    )->name('singpass.jwks');
});
