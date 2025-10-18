<?php

namespace Shokanshi\SingpassMyInfo\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Shokanshi\SingpassMyInfo\Services\Socialites\SingpassProvider;

class SingpassMyInfoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // merge package config
        $this->mergeConfigFrom(
            __DIR__.'/../../config/singpass-myinfo.php',
            'singpass-myinfo'
        );
    }

    public function boot(): void
    {
        // routes
        $this->loadRoutesFrom(__DIR__.'/../../routes/web.php');

        // views (optional)
        // $this->loadViewsFrom(__DIR__.'/../resources/views', 'singpass-myinfo');

        // publishables (optional)
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/singpass-myinfo.php' => config_path('singpass-myinfo.php'),
            ], 'singpass-myinfo-config');
        }

        Socialite::extend('singpass', function ($app) {
            $config = $app['config']['singpass-myinfo'];

            return Socialite::buildProvider(SingpassProvider::class, $config);
        });
    }
}
