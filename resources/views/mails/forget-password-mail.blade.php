<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>

    </head>

    <body>
        <h2>
            Your new password is : {{$data['randomString']}}
        </h2>
    </body>
</html>