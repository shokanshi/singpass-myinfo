<?php

namespace Shokanshi\SingpassMyInfo\Providers;

use Illuminate\Contracts\Foundation\Application;
use Laravel\Socialite\Facades\Socialite;
use Shokanshi\SingpassMyInfo\Services\Socialites\SingpassProvider;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SingpassMyInfoServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('singpass-myinfo')
            ->hasConfigFile()
            ->hasRoute('web');
    }

    public function registeringPackage(): void {}

    public function bootingPackage(): void
    {
        Socialite::extend('singpass', function (Application $app) {

            $config = app('config')['singpass-myinfo'];

            assert(is_array($config));

            return Socialite::buildProvider(SingpassProvider::class, $config);
        });
    }
}
