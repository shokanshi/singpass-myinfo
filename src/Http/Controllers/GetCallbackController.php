<?php

namespace Shokanshi\SingpassMyInfo\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class GetCallbackController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        return response()->json(json_encode(singpass()->user()));
    }
}
