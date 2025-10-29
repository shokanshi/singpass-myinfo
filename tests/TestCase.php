<?php

namespace Shokanshi\SingpassMyInfo\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Shokanshi\SingpassMyInfo\Providers\SingpassMyInfoServiceProvider;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Shokanshi\\SingpassMyInfo\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );
    }

    protected function getPackageProviders($app)
    {
        return [
            SocialiteServiceProvider::class,
            SingpassMyInfoServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app)
    {
        // make sure the config exists **before** the provider boots
        $app['config']->set(
            'singpass-myinfo',
            require __DIR__.'/../config/singpass-myinfo.php'
        );
    }

    public function getEnvironmentSetUp($app)
    {
        config()->set('database.default', 'testing');

        /*
        foreach (\Illuminate\Support\Facades\File::allFiles(__DIR__ . '/../database/migrations') as $migration) {
        (include $migration->getRealPath())->up();
        }
         */
    }
}
