<?php
ob_start();

$method = $_GET["mt"];
$openid = $_GET["op"];
$redirecturi = $_GET["ru"];

include_once("config.php");
include_once('util.php');

$url = $riceappsdk_configs["passportdomain"]."/getuserinfo.php";
$params = array('op'=>$openid);
$json = Util::getHttpResponsePOST($url, $params);
$userinfo = json_decode($json);

if($method == "LOGIN")
{
    Util::Login($userinfo);
}
else if ($method == "LOGOUT")
{
    Util::Logout();
}

header("Location:".$redirecturi);

ob_end_flush();

?>