<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use Illuminate\Http\Request;

class GetJwksController extends Controller
{
    public function __invoke(Request $request)
    {
        return response()->json(json_encode(singpass()->generateJwksForSingpassPortal()));
    }
}
