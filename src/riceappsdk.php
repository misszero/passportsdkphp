<?php

namespace Rice\Passport;

include_once('HttpClient.class.php');
include_once('Mobile_Detect.php');
include_once("config.php");
include_once('util.php');

class RiceAppSDK
{
    var $InApp = false;
    var $UserID = "";
    var $Appkey = "";
    var $Domain = "";
    var $ClientType = "";
    var $AccessMode = "";
    var $AddUserByWeixinUnlogin = "0";
    var $SiteName = "";
    var $CurrentUrl = "";
    var $getuserinfoUri = "";
    var $checkloginUri = "";
    var $adduserUri = "";
    var $loginserviceuri = "";
    var $callcenteruri = "";
    var $checkpermissionsuri = "";
    var $checkneedpermissionsuri = "";
    var $nopermissionsuri = "";
    var $setstoreiduri = "";
    var $authorizetouser = "";
    var $getstoreuri = "";
    var $weixinoauthuri = "";
    var $checkweixinoauthuri = "";
    var $weixinappid = "";
    var $weixinsecret = "";
    var $getstoreservicesuri = "";
    var $getservicebyurluri = "";
    var $bindphoneuri = "";
    var $needComplteUserInfoWithService = "";

    static function CreateSDK($appkey, $clienttype = 0, $accessmode = 1, $adduserbyweixinunlogin = 0, $sitename = "")
    {
        if(isset($appkey) || $appkey == "")
        {
            echo "必须设置AppKey，否则无法使用Passport。";
            die;
        }

        return RiceAppSDK::Create(RiceAppSDKConfig::$PassportDomain, RiceAppSDKConfig::$WeixinOauth, RiceAppSDKConfig::$WeixinAppid, RiceAppSDKConfig::$WeixinSecret, RiceAppSDKConfig::$RootDomain,
            $appkey, $clienttype, $accessmode, $adduserbyweixinunlogin, $sitename);
    }

    static function Create($passportdomain, $weixinoauth, $weixinappid, $weixinsecret, $rootdomain, $appkey, $clienttype, $accessmode, $adduserbyweixinunlogin, $sitename)
    {
        global $_SERVER;
        $Agent = $_SERVER['HTTP_USER_AGENT'];
        $domain = $_SERVER['HTTP_HOST'];
        $port = $_SERVER['SERVER_PORT'];

        $passportDomain = $passportdomain;
        $weixinOauth = $weixinoauth;
        $weixinAppid = $weixinappid;
        $weixinSecret = $weixinsecret;
        $rootDomain = $rootdomain;
        $appKey = $appkey;
        $clienTtype = $clienttype;
        $accessMode = $accessmode;
        $addUserByWeixinUnlogin = $adduserbyweixinunlogin;
        $siteName = $sitename;

        $sdk = new RiceAppSDK();

        $sdk->CurrentUrl = "http://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
        $sdk->Appkey = $appKey;

        if(empty($clienTtype))
        {
            $sdk->ClientType = "2";
        }
        else
        {
            if($clienTtype == "0")
            {
                $detect = new Mobile_Detect();
                $sdk->ClientType = ($detect->isMobile() ? "2" : "1");
            }
            else
            {
                $sdk->ClientType = $clienTtype;
            }
        }

        if(empty($accessMode))
        {
            $sdk->AccessMode = "1";
        }
        else
        {
            $sdk->AccessMode = $accessMode;
        }

        $sdk->AddUserByWeixinUnlogin = $addUserByWeixinUnlogin;
        $sdk->SiteName = $siteName;

        $sdk->getuserinfoUri = $passportDomain."/getuserinfo.php";
        $sdk->checkloginUri = $passportDomain."/checklogin.php";
        $sdk->adduserUri = $passportDomain."/adduser.php";
        $sdk->loginserviceuri = $passportDomain."/login.php";
        $sdk->callcenteruri = $passportDomain."/call_center.php";
        $sdk->checkpermissionsuri = $passportDomain."/permission/checkpermissions.php";
        $sdk->checkneedpermissionsuri = $passportDomain."/permission/checkneedpermissions.php";
        $sdk->nopermissionsuri = $passportDomain."/permission/nopermissions.php";
        $sdk->getservicebyurluri = $passportDomain."/permission/getservicebyurl.php";
        $sdk->needComplteUserInfoWithService = $passportDomain."/permission/NeedComplteUserInfoWithService.php";
        $sdk->setstoreiduri = $passportDomain."/permission/setstoreid.php";
        $sdk->authorizetouser = $passportDomain."/permission/authorizetouser.php";
        $sdk->getstoreuri = $passportDomain."/services/getstore.php";
        $sdk->weixinoauthuri = $weixinOauth;
        $sdk->checkweixinoauthuri = $passportDomain."/checkweixinoauth1.php";
        $sdk->weixinappid = $weixinAppid;
        $sdk->weixinsecret = $weixinSecret;
        $sdk->getstoreservicesuri = $passportDomain."/services/getstoreservices.php";
        $sdk->bindphoneuri = $passportDomain."/services/user/bindphone.php";

        if(preg_match('/ricebrowser/', $Agent))
        {
            $sdk->InApp = true;
            list($agentUrl, $agentParamStr) = explode("ricebrowser?", $Agent);
            list($paramUidStr, $paramNameStr) = explode("&", $agentParamStr);
            list($paramUidKey, $paramUidValue) = explode("=", $paramUidStr);
            $sdk->UserID = $paramUidValue;
        }

        $sdk->Domain = $domain;

        $sdk->Check();

        /*if($addUserByWeixinUnlogin == "1")
        {
            $sdk->ToAddUserByWeixin($_SERVER['REQUEST_URI']);
        }*/

        return $sdk;
    }

    /*
     * 构造检查微信用户权限的回调页地址
     */
    private function CreateCheckWeixinOAuthCallbackUri($uri, $queries)
    {
        $tmpQueries = $queries;
        foreach($tmpQueries as $x_key=>$x_value) {
            $tmpQueries[$x_key] = str_replace("&", "|", $x_value);
        }

        $cbjsonobj = array("uri"=>$uri, "qs"=>$tmpQueries);
        $tmpstr1 = json_encode($cbjsonobj);
        $tmpstr2 = addslashes($tmpstr1);
        $tmpstr3 = str_replace('\"', '||', $tmpstr2);
        $callbackuri = $tmpstr3;

        return $callbackuri;
    }

    /*
     * 检查Passport的登陆状态，根据所处环境进行不同操作。
     * 已经有登陆信息的情况下直接调用Util::Login()，没有登陆信息的情况下分成以下几种情况：
     * 如果运行在稻米APP内置浏览器时，判断APP是否登陆，已登陆则获取APP中保存的用户信息并进行登陆操作。
     * 如果运行在微信内置浏览器时，获取微信用户的UnionID并检查是否跟Passport用户进行绑定，已绑定则直接用该用户进行登陆。为了避免重复判断，系统会判断IsBindingWeixin是否为“unbind”，代表微信用户未绑定，不需要重复校验了。
     * 如果运行在普通浏览器时，直接调用Util::Logout()。
     */
    public function Check()
    {
        if($this->IsLogin())
        {
            $userinfo = $this->GetUserInfo($this->GetOpenID());
            if($this->IsInWeixin())
            {
                if($_SERVER['REQUEST_METHOD'] == "GET") {
                    $redirecturi = $_SERVER['REQUEST_URI'];
                    $weixinunionid = $this->GetWeixinUnionID();
                    if ($weixinunionid == "" || $weixinunionid != $userinfo->WeixinUnionID) {
                        Util::Logout();
                        $this->GotoWeixinAuth($redirecturi);
                    }
                }
            }
            Util::Login($userinfo);
        }
        else if($this->IsInApp() && $this->AppIsLogin())
        {
            $m_appkey = $this->Appkey;
            $m_userid = $this->UserID;
            $url = $this->checkloginUri;
            $params = array('ak'=>$m_appkey, 'uid'=>$m_userid);
            $result = json_decode(HttpClient::quickPost($url, $params));
            $result_openid = $result->openid;

            Util::Login($this->GetUserInfo($result_openid));
        }
        else if($this->IsInWeixin() && $this->IsBindingWeixin() != "unbind")
        {
            if($_SERVER['REQUEST_METHOD'] == "GET")
            {
                $redirecturi = $_SERVER['REQUEST_URI'];
                $weixinunionid = $this->GetWeixinUnionID();

                /*if($weixinunionid == "")
                {
                    $this->GotoWeixinAuth($redirecturi);
                }
                else
                {
                    $this->RedirectCheckWeixinOAuth($this->Appkey, $redirecturi, $this->Domain, $this->SiteName, $weixinunionid);
                }*/

                $this->GotoWeixinAuth($redirecturi);
            }
        }
        else
        {
            Util::Logout();
        }

    }

    private function GotoWeixinAuth($redirecturi)
    {
        if($this->AddUserByWeixinUnlogin == "1")
        {
            $queries = array("ak"=>$this->Appkey, "ru"=>$redirecturi, "dm"=>$this->Domain, "wsn"=>$this->SiteName, "aul"=>$this->AddUserByWeixinUnlogin);
            $callbackuri = $this->CreateCheckWeixinOAuthCallbackUri($this->checkweixinoauthuri, $queries);
            $this->CheckWeixinOAuth("snsapi_userinfo", $callbackuri);
        }
        else
        {
            $queries = array("ak"=>$this->Appkey, "ru"=>$redirecturi, "dm"=>$this->Domain, "wsn"=>$this->SiteName);
            $callbackuri = $this->CreateCheckWeixinOAuthCallbackUri($this->checkweixinoauthuri, $queries);
            //$this->CheckWeixinOAuth("snsapi_base", $callbackuri);
            $this->CheckWeixinOAuth("snsapi_userinfo", $callbackuri);
        }

    }

    /*
    * 跳转到微信用户验证页，判断当前的微信用户UnionID是否与Passport用户绑定，如果是则用该用户登陆，如果没有绑定则直接返回。
    *
    * 参数：
    * $appkey - Passport的Appkey
    * $redirecturi - 回调地址
    * $domain - 回调地址域名部分
    * $weixinunionid - 微信用户的UnionID
    *
    * 返回值：
    * 无
    */
    private function RedirectCheckWeixinOAuth($appkey, $redirecturi, $domain, $sitename, $weixinunionid)
    {
        $reduri = urlencode($redirecturi);
        $url = sprintf("%s?ak=%s&ru=%s&dm=%s&wsn=%s&wxuid=%s", $this->checkweixinoauthuri, $appkey, $reduri, $domain, $sitename, $weixinunionid);
        $this->Redirect($url);
    }

    /*
    * 判断当前微信账号是否与用户绑定，该返回值用于避免当微信用户账号未绑定时，Passport重复跳转到微信用户验证页面的情况。
    * 返回值：
    * 1-已绑定 0-未绑定 -1-未确认
    */
    private function IsBindingWeixin()
    {
        $isbinding = "";
        if(!empty($_COOKIE["rice_passport_weixinisbinding"]))
        {
            $isbinding = $_COOKIE["rice_passport_weixinisbinding"];
        }

        return $isbinding;
    }

    /*
    * 返回当前缓存的微信用户UnionID
    * 返回值：
    * 微信用户UnionID，未缓存的情况下返回空字符串。
    */
    public function GetWeixinUnionID()
    {
        $weixinunionid = "";
        if(!empty($_COOKIE["rice_passport_weixinunionid"]))
        {
            $weixinunionid = $_COOKIE["rice_passport_weixinunionid"];
        }
        return $weixinunionid;
    }

    //校验当前微信账号是否在Passport中已经绑定
    private function CheckWeixinOAuth($scope, $callbackuri)
    {
        $appid = $this->weixinappid;
        $redirect_uri = $this->weixinoauthuri."?cb=".$callbackuri;
        $weixinoauthauthorizeuri = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=1#wechat_redirect";
        $url = sprintf($weixinoauthauthorizeuri, $appid, $redirect_uri, $scope);
        $this->Redirect($url);
    }

    private function CheckNeedPermissions()
    {
        $serviceurl = $this->CurrentUrl;

        $url = $this->checkneedpermissionsuri;
        $params = array('serviceurl'=>$serviceurl);
        $str = HttpClient::quickPost($url, $params);

        $ajax_str = json_decode($str);

        $need = $ajax_str->data->need;

        if($need == 1)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    private function CheckHasPermissions($userid, $storeid, $serviceurl)
    {
        $url = $this->checkpermissionsuri;
        $params = array('userid'=>$userid, 'storeid'=>$storeid, 'serviceurl'=>$serviceurl);
        $str = HttpClient::quickPost($url, $params);

        $ajax_obj = json_decode(trim($str,chr(239).chr(187).chr(191)));
        $result = $ajax_obj->data->result;

        if($result == 2)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    public function CheckPermissionsByUrl($serviceurl)
    {
        $userinfo = $this->GetUserInfo($this->GetOpenID());
        $userid = $userinfo->UserID;
        $storeid = $this->GetStoreID();

        $result = $this->CheckHasPermissions($userid, $storeid, $serviceurl);
        if(!$result && $storeid != 0)
        {
            $result = $this->CheckHasPermissions($userid, 0, $serviceurl);
        }

        return $result;
    }

    public function CheckPermissions()
    {
        //已经登陆则判断用户是否有该页面的访问权限，如果没有登陆则判断该页面是否需要访问权限，如果需要则跳转到登陆页面。
        if($this->IsLogin())
        {
            $serviceurl = $this->CurrentUrl;
            $referer = "";
            if(array_key_exists("HTTP_REFERER", $_SERVER))
            {
                $referer = $_SERVER['HTTP_REFERER'];
            }
            $result = $this->CheckPermissionsByUrl($serviceurl);
            if(!$result)
            {   //无访问权限
                $this->Redirect($this->nopermissionsuri."?referer=".urlencode($referer));
            }
            else
            {
                $result = $this->NeedComplteUserInfoWithService($this->CurrentUrl);
                if($result == 1)
                {
                    $this->RebindPhone($_SERVER['REQUEST_URI']);
                }
            }
        }
        else
        {
            if($this->CheckNeedPermissions())
            {
                $this->ToLogin($_SERVER['REQUEST_URI']);
            }
        }
    }

    public function GetStoreID()
    {
        $storeid = -1;
        if(!empty($_COOKIE["rice_passport_storeid"]))
        {
            $storeid = $_COOKIE["rice_passport_storeid"];
        }
        return $storeid;
    }

    public function SetStoreID($storeid)
    {
        $cookie_timeout = 3600*24*30;
        Util::SetCookies("rice_passport_storeid", $storeid, $cookie_timeout);
    }

    public function ClearStoreID()
    {
        $cookie_timeout = 3600;
        Util::SetCookies("rice_passport_storeid", "", $cookie_timeout);
    }

    public function GetStore()
    {
        $result = null;
        $storeid = $this->GetStoreID();
        if($storeid > 0)
        {
            $url = $this->getstoreuri;
            $params = array('id'=>$storeid);
            $str = HttpClient::quickPost($url, $params);
            $ajax_str = json_decode(trim($str,chr(239).chr(187).chr(191)));
            $result = $ajax_str->data->result;
        }

        return $result;
    }

    public function AuthorizeToUser($userid, $rolecode)
    {
        $serviceurl = $this->CurrentUrl;
        $storeid = $this->GetStoreID();
        $url = $this->authorizetouser;
        $params = array('userid'=>$userid, 'storeid'=>$storeid, 'rolecode'=>$rolecode);
        $str = HttpClient::quickPost($url, $params);

        $ajax_str = json_decode($str);

        $result = $ajax_str->data->result;

        return $result;
    }

    private function Redirect($url)
    {
        /*echo "<html><script language='javascript' type='text/javascript'>";
        echo "window.location.href='$url';";
        echo "</script></html>";*/

        header("Location:".$url);
        exit(0);

        /*$ch = curl_init();
        curl_setopt ($ch, CURLOPT_URL, $url);
        curl_exec ($ch);
        curl_close ($ch);*/
    }

    //判断当前是否登陆
    public function IsLogin()
    {
        $openid = $this->GetOpenID();
        if(empty($openid))
        {
            return false;
        }
        else
        {
            if($this->IsInApp())
            {
                $userinfo = $this->GetUserInfo($openid);
                if(!empty($userinfo) && !empty($this->UserID) && ($userinfo->UserID == $this->UserID))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return true;
            }
        }
    }

    //判断App是否已经登陆（只要当嵌入到App时才需要检查）
    public function AppIsLogin()
    {
        $appIsLogin = false;
        if($this->IsInApp() == true && !empty($this->UserID))
        {
            $appIsLogin = true;
        }
        return $appIsLogin;
    }

    //判断当前站点是否运行在稻米APP下面
    public function IsInApp()
    {
        return $this->InApp;
    }

    //判断当前站点是否运行在微信浏览器下面
    public function IsInWeixin()
    {
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        if (strpos($user_agent, 'MicroMessenger') === false) {
            return false;
        } else {
            return true;
        }
    }

    //获取当前的OpenID，为空时候表示尚未登陆
    public function GetOpenID()
    {
        $openid = "";
        if(!empty($_COOKIE["openid"]))
        {
            $openid = $_COOKIE["openid"];
        }
        return $openid;
    }

    //获取当前的用户信息
    public function GetUserInfo($openid)
    {
        $url = $this->getuserinfoUri;
        $params = array('op'=>$openid);
        $entites = HttpClient::quickPost($url, $params);

        return json_decode(trim($entites,chr(239).chr(187).chr(191)));
    }

    /*
     * 跳转到Passprot Service的callcenter页,用户调用Passport Service的服务都通过callcenter，然后由于callcenter路由到指定的服务，而不是直接与服务交互。
     *
     * 参数
     * $method - 要调用的服务
     * $redirecturi - 回调页面的地址
     * $chekweixinoauth - 是否进行微信用户权限校验，默认不需要
     *
     * 返回值
     * 无
     */
    private function ToCallCenter($method, $redirecturi, $chekweixinoauth = false)
    {
        if($chekweixinoauth == true && $this->IsInWeixin())
        {
            $queries = array("mt"=>$method, "ak"=>$this->Appkey, "ru"=>$redirecturi, "dm"=>$this->Domain, "wsn"=>$this->SiteName);
            $callbackuri = $this->CreateCheckWeixinOAuthCallbackUri($this->callcenteruri, $queries);
            $this->CheckWeixinOAuth("snsapi_userinfo", $callbackuri);
        }
        else
        {
            $reduri = urlencode($redirecturi);
            $url = sprintf("%s?mt=%s&ak=%s&ru=%s&dm=%s&wsn=%s", $this->callcenteruri, $method, $this->Appkey, $reduri, $this->Domain, $this->SiteName);
            $this->Redirect($url);
        }
    }

    /*
     * 根据微信账号新增一个用户
     *
     * 参数：
     * $redirecturi - 回调页
     */
    public function ToAddUserByWeixin($redirecturi)
    {
        if(!$this->IsLogin() && $this->IsInWeixin())
        {
            $method = "adduserbyweixin";
            $this->ToCallCenter($method, $redirecturi, true);
        }
    }

    //跳转到登陆页
    public function ToLogin($redirecturi)
    {

        $method = "login";
        if($this->ClientType == "1")
        {
            $method = "login_pc";
        }
        else
        {
            $method = "login";
        }

        if($this->InApp)
        {
            $this->CallJsSDKFunc("Login");
        }
        else
        {
            $this->ToCallCenter($method, $redirecturi, true);
        }
    }

    //调整到注册页
    public function ToRegister($redirecturi)
    {
        $method = "register";
        if($this->ClientType == "1")
        {
            $method = "register_pc";
        }
        else
        {
            $method = "register";
        }

        if($this->InApp)
        {
            $this->CallJsSDKFunc("Register");
        }
        else
        {
            $this->ToCallCenter($method, $redirecturi, true);
        }
    }

    private function CallJsSDKFunc($fnname)
    {
        echo "<script src=\"http://res.waitme.mobi/public/RiceJsSDK/RiceJsSDK.js?i=1\"></script>";
        echo sprintf("<script>RiceAppSDK.%s();</script>", $fnname);
    }

    //注销登陆用户
    public function Logout()
    {
        Util::Logout();
    }

    /*
    * 打开修改密码页面
    * $redirecturi 回调地址
    */
    public function ChangePassword($redirecturi)
    {
        $method = "changepassword";
        if($this->ClientType == "1")
        {
            $method = "changepassword_pc";
        }
        else
        {
            $method = "changepassword";
        }

        if($this->InApp)
        {
            echo "<script>window.rice.changepassword();</script>";
        }
        else
        {

            $this->ToCallCenter($method, $redirecturi);
        }
    }

    /*
    * 打开绑定手机号码页面
    * $redirecturi 回调地址
    */
    public function RebindPhone($redirecturi)
    {
        $method = "rebindphone";
        if($this->ClientType == "1")
        {
            $method = "rebindphone_pc";
        }
        else
        {
            $method = "rebindphone";
        }

        if($this->InApp)
        {
            echo "<script>window.rice.rebindphone();</script>";
        }
        else
        {
            $this->ToCallCenter($method, $redirecturi);
        }
    }

    public function ToUserCenter($redirecturi)
    {
        $method = "usercenter";
        if($this->ClientType == "1")
        {
            $method = "usercenter";
        }
        else
        {
            $method = "usercenter";
        }

        if($this->InApp)
        {
            echo "<script>window.rice.usercenter();</script>";
        }
        else
        {
            $this->ToCallCenter($method, $redirecturi);
        }
    }

    /*
    * 新增一个用户
    * $phone 回调地址
    * 返回值 { "error" : errorcode, "errorstr" : errorstr, "userinfo": userinfo }。 当error为0时代表没有错误，可通过userinfo获取新增的user信息；若为1时代表有错误，错误信息在可以在errorstr中获取。
    */
    public function AddUser($phone)
    {
        $url = $this->adduserUri;
        $params = array('ph'=>$phone);
        $result = json_decode(HttpClient::quickPost($url, $params));
        return $result;
    }

    /*
    * 后台登陆
    * $redirecturi 回调地址
    * $username 用户名（手机号码）
    * $password 密码
    */
    public function Login($redirecturi, $username, $password)
    {
        $reduri = urlencode($redirecturi);
        if($this->InApp)
        {
            echo "<script>window.rice.login();</script>";
        }
        else
        {
            $url = sprintf("%s?ak=%s&ru=%s&dm=%s&mi=%s&pwd=%s", $this->loginserviceuri, $this->Appkey, $reduri, $this->Domain, $username, $password);
            $this->Redirect($url);
        }
    }

    /*
     * 返回当前用户的商家后台权限
     *
     * 参数：
     * $openid - Passport用户OpenID
     *
     * 返回值：
     * 权限列表 { "ServiceID" : ServiceID, "ServiceName" : ServiceName, "ServiceUrl" : ServiceUrl }
     * ServiceID - 服务ID
     * ServiceName - 服务名称
     * ServiceUrl - 服务的唯一资源定位符
     */
    public function GetStoreServices($openid)
    {
        $url = $this->getstoreservicesuri;
        $params = array('op'=>$openid);
        $str = HttpClient::quickPost($url, $params);
        $ajax_obj = json_decode(trim($str,chr(239).chr(187).chr(191)));
        $result = $ajax_obj->data->result;
        return $result;
    }

    public function GetServiceByUrl($serviceurl)
    {
        $url = $this->getservicebyurluri;
        $params = array('serviceurl'=>$serviceurl);
        $str = HttpClient::quickPost($url, $params);
        $ajax_obj = json_decode(trim($str,chr(239).chr(187).chr(191)));
        $result = $ajax_obj->data;
        return $result;
    }

    public function NeedComplteUserInfoWithService($serviceurl)
    {
        $url = $this->needComplteUserInfoWithService;

        $openid = $this->GetOpenID();

        $params = array('serviceurl'=>$serviceurl, 'op'=>$openid);
        $str = HttpClient::quickPost($url, $params);
        $ajax_obj = json_decode(trim($str,chr(239).chr(187).chr(191)));
        $result = $ajax_obj->data;
        return $result;
    }

    public function BindPhone($mobile)
    {
        $url = $this->bindphoneuri;
        $openid = $this->GetOpenID();

        $params = array('op'=>$openid, 'mobile'=>$mobile);
        $str = HttpClient::quickPost($url, $params);
        $json_obj = json_decode(trim($str,chr(239).chr(187).chr(191)));

        $code = $json_obj->code;
        if($code == "0")
        {
            return true;
        }
        else
        {
            $error = $json_obj->error;
            return $error;
        }
    }
}

//return RiceAppSDK::Create($riceappsdk_configs);

?>