<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;

class GetAuthorizationController extends Controller
{
    public function __invoke(Request $request)
    {
        return Socialite::driver('singpass')->redirect();
    }
}
