<?php
/*
//$riceappsdk_configs["appkey"] = "3b32610e-f611-11e4-b179-38eaa78c73bb";
$riceappsdk_configs["passportdomain"] = "http://passport.waitme.mobi:20080"; //passport service的根目录
//$riceappsdk_configs["client_type"] = "0"; //客户端类型 : 0-设备自适应 1-PC端 2-移动端
//$riceappsdk_configs["access_mode"] = "2"; //接入模式 : 1-内部访问 2-外部访问
$riceappsdk_configs["weixin_oauth"] = "http://weixin.rice.ec/weixinoauth.php"; //微信用户授权文件的路径
$riceappsdk_configs["weixin_appid"] = "wx41b43020af25e8e0"; //微信公众号的应用ID
$riceappsdk_configs["weixin_secret"] = "0523dd82716a7732b6d09bd98c1a3b32"; //微信公众号的应用秘钥
$riceappsdk_configs["rootdomain"] = "waitme.mobi"; //根域
//$riceappsdk_configs["adduserbyweixin_unlogin"] = "0"; //开启在未登陆的情况下将当前微信账号自动绑定到Passprot的功能（0-未开启 1-开启）
//$riceappsdk_configs["sitename"] = ""; //子程序名。当一个域名下面有多个子程序时，需要填写该参数，参数内容与站点授权配置的子程序名要一致。*/

class RiceAppSDKConfig
{
    static $PassportDomain = "http://passport.waitme.mobi:20080";
    static $WeixinOauth = "http://weixin.rice.ec/weixinoauth.php";
    static $WeixinAppid = "wx41b43020af25e8e0";
    static $WeixinSecret = "0523dd82716a7732b6d09bd98c1a3b32";
    static $RootDomain = "waitme.mobi";
}

?> 