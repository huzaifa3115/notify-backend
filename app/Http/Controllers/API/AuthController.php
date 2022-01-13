<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {

        $userData = $request->all();
        $userData['password'] = bcrypt($request->password);

        $user = User::create($userData);

        $accessToken = $user->createToken('authToken')->accessToken;
        return response()->json([
            'success' => true,
            'message' => 'User has been created',
            'data' => ['user' => $user, 'access_token' => $accessToken],
        ]);
    }

    public function login(Request $request)
    {
        $loginData = $request->all();

        if (!auth()->attempt($loginData)) {
            return response()->json(['success' => false, 'message' => 'Invalid Credentials']);
        }

        $accessToken = auth()->user()->createToken('authToken')->accessToken;
        return response()->json([
            'success' => true,
            'data' => ['user' => auth()->user(), 'access_token' => $accessToken],
        ]);

    }
}
