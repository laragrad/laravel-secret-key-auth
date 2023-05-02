<?php

namespace Laragrad\SecretKeyAuth;

use App\Models\User;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Laravel\Sanctum\Sanctum;
use Laravel\Sanctum\TransientToken;

class Guard
{

    /**
     * @param Request $request
     * @return void
     */
    public function __invoke(Request $request)
    {
        if ($secretKey = $request->header('x-secret-key')) {
            if ($userId = config("secret_key.secrets.{$secretKey}")) {
                return User::find($userId);
            }
        }
    }

}
