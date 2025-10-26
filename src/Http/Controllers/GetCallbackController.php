<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;

class GetCallbackController extends Controller
{
    public function __invoke(Request $request)
    {
        return response()->json(json_encode(Socialite::driver('singpass')->user()));
    }
}
