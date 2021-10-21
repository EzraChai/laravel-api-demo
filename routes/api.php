<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use \App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
//  Public Routes
Route::get('/products',[ProductController::class, 'index']);
Route::get('/products/{id}',[ProductController::class, 'show']);
Route::get('/products/search/{name}',[ProductController::class,'search']);
Route::post('/register',[AuthController::class, 'register']);
Route::post('/login',[AuthController::class, 'login']);

//Route::resource('product',ProductController::class);

//  Protected Routes
Route::group(['middleware'=> 'auth:sanctum'], function (){
    Route::post('/products',[ProductController::class, 'store']);
    Route::match(['put', 'patch'],'/products',[ProductController::class, 'update']);
    Route::delete('/products',[ProductController::class, 'delete']);
    Route::post('/logout',[AuthController::class,'logout']);
});



Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
