<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

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



Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/forgot-password',[AuthController::class, 'forgotPassword']);

Route::group(['middleware' => ['auth:sanctum']], function () {

    Route::post('/add-permission', [AuthController::class, 'setPermission']);
    Route::get('get-permission-list',[AuthController::class, 'getPermissionList']);
    Route::post('/assign-permission',[AuthController::class, 'assignPermission']);
    Route::post('/update-password',[AuthController::class, 'updatePassword']);    
    Route::post('/logout', [AuthController::class, 'logout']);
});
