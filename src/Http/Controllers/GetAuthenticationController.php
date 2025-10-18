<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;

class GetAuthenticationController extends Controller
{
    public function __invoke(Request $request)
    {
        return Socialite::driver('singpass')->redirect();
    }
}
