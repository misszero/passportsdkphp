<?php

if(!isset($_SESSION)){
   session_start();
}

class Handler
{
    public function OnLogin($userinfo)
    {
        $userData = $userinfo;
        $userId = $userData->UserID;
        $userName = $userData->UserName;
        $isLogin = 1;

        $_SESSION["userid"] = $userData->UserID;
        $_SESSION["username"] = $userData->UserName;
        $_SESSION["islogin"] = 1;
    }

    public function OnLogout()
    {
        $userData = "";
                $userId = "";
                $userName = "";
                $isLogin = 0;

                $_SESSION["userid"] = "";
                        $_SESSION["username"] = "";
                        $_SESSION["islogin"] = 0;
    }
}

?>