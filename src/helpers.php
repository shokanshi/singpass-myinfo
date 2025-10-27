<?php

use Laravel\Socialite\Facades\Socialite;
use Shokanshi\SingpassMyInfo\Services\Socialites\SingpassProvider;

if (! function_exists('singpass')) {
    function singpass(): SingpassProvider
    {
        /** @var SingpassProvider $driver */
        $driver = Socialite::driver('singpass');

        return $driver;
    }
}
