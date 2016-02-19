<?php

include_once('handler.php');
include_once("config.php");

class Util
{
    //public static $Configs;
    public static $AccessMode;
    public static $RootDomain;

    static function Login($userinfo)
    {
        if(self::$AccessMode == "2")
        {
            $cookie_timeout = 3600*24*30;
            self::SetCookies("openid", $userinfo->OpenID, $cookie_timeout);

            $_COOKIE["openid"] = $userinfo->OpenID;
        }

        Handler::OnLogin($userinfo);
    }

    static function Logout()
    {
        $cookie_timeout = 0;
        self::SetCookies("openid", "", $cookie_timeout);

        if(self::$AccessMode == "2")
        {
            setcookie("openid", "", time()+$cookie_timeout, "/");
        }

        self::SetCookies("rice_passport_weixinunionid", "", $cookie_timeout);
        self::SetCookies("rice_passport_weixinisbinding", "", $cookie_timeout);

        Handler::OnLogout();
    }

    static function SetConfigs($accessmode, $rootdomain)
    {
        if(empty($accessmode))
        {
           self::$AccessMode = "1";
        }
        else
        {
            self::$AccessMode = $accessmode;
        }

        self::$RootDomain = $rootdomain;
    }

    static function SetCookies($key, $value, $timeout)
    {
        setcookie($key, $value, time()+$timeout, "/", self::$RootDomain);
    }

    static function getHttpResponsePOST($url, $para, $input_charset = '') {

        if (trim($input_charset) != '') {
            $url = $url."_input_charset=".$input_charset;
        }
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_HEADER, 0 ); // 过滤HTTP头
        curl_setopt($curl,CURLOPT_RETURNTRANSFER, 1);// 显示输出结果
        curl_setopt($curl,CURLOPT_POST,true); // post传输数据
        curl_setopt($curl,CURLOPT_POSTFIELDS,$para);// post传输数据
        $responseText = curl_exec($curl);
        //var_dump(curl_error($curl));//如果执行curl过程中出现异常，可打开此开关，以便查看异常内容
        curl_close($curl);

        return $responseText;
    }
}

//Util::SetConfigs($riceappsdk_configs);
//Util::SetConfigs($accessmode, $rootdomain);

?>