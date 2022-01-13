<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Http\Request;
use Validator;
use App\Http\Requests\LoginRequest;


class AuthController extends Controller
{
    public function register(LoginRequest $request)
    {
        return "Success";
        // $validation = Validator::make($request->all(), [
        //     'username' => 'required|unique:users, username',
        //     'email' => 'email|required|unique:users',
        //     'password' => 'required',
        // ]);

        // $validatedData['password'] = bcrypt($request->password);
        // dd($request->all());
        // $user = User::create($validatedData);

        // $accessToken = $user->createToken('authToken')->accessToken;

        // return response(['user' => $user, 'access_token' => $accessToken]);
    }

    public function login(Request $request)
    {
        $loginData = $request->validate([
            'email' => 'email|required',
            'password' => 'required',
        ]);

        if (!auth()->attempt($loginData)) {
            return response(['message' => 'Invalid Credentials']);
        }

        $accessToken = auth()->user()->createToken('authToken')->accessToken;

        return response(['user' => auth()->user(), 'access_token' => $accessToken]);

    }
}
