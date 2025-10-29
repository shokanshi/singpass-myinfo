<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class GetAuthorizationController extends Controller
{
    public function __invoke(Request $request): RedirectResponse
    {
        return singpass()->redirect();
    }
}
