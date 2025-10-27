<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use Illuminate\Http\Request;

class GetAuthorizationController extends Controller
{
    public function __invoke(Request $request)
    {
        return singpass()->redirect();
    }
}
