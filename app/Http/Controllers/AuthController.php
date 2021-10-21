<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Register
     *
     * @param  Request  $request
     * @return array
     */
    public function register(Request $request)
    {
        $fields = $request -> validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|min:6|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password']),
        ]);

        $token =  $user -> createToken('myapptoken') -> plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        return [$response, 201];
    }

    /**
     * Login
     *
     * @param  Request  $request
     * @return array|\Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $fields = $request -> validate([
            'email' => 'required|string|email',
            'password' => 'required|string|min:6'
        ]);

        $user = User::where('email',$fields['email']) -> first();

        //  Check Password
        if(!$user || !Hash::check($fields['password'], $user -> password)){
            return Response([
                'message' =>  'Bad creds'
            ], 401);
        }

        $token =  $user -> createToken('myapptoken') -> plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        return [$response, 201];
    }


    /**
     * Logout
     *
     * @param  Request  $request
     * @return array
     */
    public function logout(Request $request){
        auth()->user()->tokens()->delete();

        return [
            'message'  => 'Logout successfully.'
        ];
    }
}
