<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Validator;
use App\Models\User;
use App\Models\Permission;
use App\Models\UserPermission;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Nette\Utils\Random;
use Symfony\Component\HttpFoundation\RateLimiter\RequestRateLimiterInterface;

class AuthController extends Controller
{
    public function register(Request $request)
    {


        $validator = Validator::make($request->all(), [
            'name' => "required",
            "phone" => "required",
            "role" => "required",
            "email" => "required|email",
            "password" => "required"

        ]);

        if ($validator->fails()) {
            return response()->json(["status_code" => 400, "error" => $validator->errors()]);
        }

        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->phone = $request->phone;
        $user->role = $request->role;
        $user->password = bcrypt($request->password);
        $user->Save();

        return response()->json([
            'status_code' => 200,
            'message' => "user created successfully!"
        ]);
    }


    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            "email" => "required|email",
            "password" => "required"

        ]);

        if ($validator->fails()) {
            return response()->json(["status_code" => 400, "message" => "bad Request"]);
        }

        $credential = request(['email', 'password']);

        if (!Auth::attempt($credential)) {


            return response()->json([
                'status_code' => 500,
                "message" => "unauthorized"
            ]);
        }

        $user = User::where('email', $request->email)->first();

        $tokenResult = $user->createToken('authToken')->plainTextToken;


        $permisson = UserPermission::leftJoin('permissions', 'permissions.id', '=', 'user_permissions.permission_id')
            ->select('user_permissions.permission_id', "permissions.title")
            ->where('user_permissions.user_id', Auth::id())
            ->get();

        $data = [
            "user_id" => Auth::id(),
            "email" => Auth::user()->email,
            "role" => Auth::user()->role,
            "name" => Auth::user()->name,
            "phone" => Auth::user()->phone,
            "permissions" => $permisson

        ];

        return response()->json([
            'status_code' => 200,
            'data' =>   $data,
            "token" => $tokenResult

        ]);
    }

    public function logout(Request $request)
    {

        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status_code' => 200,
            'message' => "Token Deleted successfully"

        ]);
    }


    public function getPermissionList()
    {

        if (Auth::user()->role == "admin") {

            $permissionList =  Permission::all();

            if ($permissionList) {
                return response()->json([
                    'status_code' => 200,
                    'message' => "Success",
                    'data' => $permissionList

                ]);
            } else {
                return response()->json([
                    'status_code' => 200,
                    'message' => "Empty Table",
                    'data' => []

                ]);
            }
        } else {
            return response()->json(["status_code" => 400, "message" => "This user is not authorized to access this route"]);
        }
    }


    public function setPermission(Request $request)
    {

        $validator = Validator::make($request->all(), [
            "title" => "required",
        ]);

        if ($validator->fails()) {
            return response()->json(["status_code" => 400, "errors" => $validator->errors()]);
        }

        if (Auth::user()->role == "admin") {

            $permission = new Permission();
            $permission->title = $request->title;
            $permission->status = 1;
            $permission->Save();

            return response()->json([
                'status_code' => 200,
                'message' => "Permission created successfully"

            ]);
        } else {
            return response()->json(["status_code" => 400, "message" => "This user is not authorized to access this route"]);
        }
    }



    public function assignPermission(Request $request)
    {
        $validator = Validator::make($request->all(), [
            "user_id" => "required",
            "permission_id" => "required"
        ]);

        if ($validator->fails()) {
            return response()->json(["status_code" => 400, "errors" => $validator->errors()]);
        }

        if (Auth::user()->role == "admin") {

            $user_permission = new  UserPermission();
            $user_permission->user_id = $request->user_id;
            $user_permission->permission_id = $request->permission_id;
            $user_permission->Save();

            return response()->json([
                'status_code' => 200,
                'message' => "Permission assigned successfully"
            ]);
        } else {
            return response()->json(["status_code" => 400, "message" => "This user is not authorized to access this route"]);
        }
    }


    public function updatePassword(Request $request)
    {

        $validator = Validator::make($request->all(), [
            "old_password" => "required",
            "new_password" => "required",
            "confirm_password" => "required"

        ]);

        if ($validator->fails()) {
            return response()->json(["status_code" => 400, "errors" => $validator->errors()]);
        }



        $hashedPassword = Auth::user()->password;

        if (\Hash::check($request->old_password, $hashedPassword && $request->confirm_password == $request->new_password)) {

            if (!\Hash::check($request->confirm_password, $hashedPassword)) {

                $users = User::find(Auth::id());
                $users->password = bcrypt($request->confirm_password);
                $users->Save();

                return response()->json([
                    'status_code' => 200,
                    'message' => "Password updated successfully"
                ]);
            } else {

                return response()->json([
                    'status_code' => 400,
                    'message' => "new password can not be the old password!"
                ]);
            }
        } else {
            return response()->json([
                'status_code' => 400,
                'message' => "Password not matched"
            ]);
        }
    }


    public function forgotPassword(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => "required|email"
        ]);

        if ($validator->fails()) {
            return response()->json(["status_code" => 400, "errors" => $validator->errors()]);
        }


        $user = User::where('email', $request->email)->first();

        if ($user) {

            $randomString = Rand(1111111, 9999999);
            $data = ['name' => "arman", 'randomString' => $randomString];
            $user['to'] = $request->email;
            Mail::send('mails.forget-password-mail', ['data' => $data], function ($messages) use ($user, $data) {

                $messages->to($user['to']);
                $messages->subject('Reset Password for ReliSource HRMS');
            });

            $user = User::where('email', $request->email)->update(
                [
                    'password' => bcrypt($randomString)
                ]
            );

            return response()->json([
                'status_code' => 404,
                'message' => "New password sent to your email"
            ]);
        } else {
            return response()->json([
                'status_code' => 404,
                'message' => "Email address is not registered"
            ]);
        }
    }
}
