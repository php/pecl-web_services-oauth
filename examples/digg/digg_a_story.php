<?php

include('config.inc.php');

try {
$oauth = new OAuth(DIGG_CONSUMER_KEY, DIGG_CONSUMER_SECRET, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_FORM);
$request_token = $oauth->getRequestToken("http://services.digg.com/1.0/endpoint?method=oauth.getRequestToken");

echo "Go to http://digg.com/oauth/authorize?oauth_token={$request_token["oauth_token"]} and enter the code (PIN) given at the end of the flow @ digg\n";
$in = fopen("php://stdin", "r");
$verifier = fgets($in, 255);

echo "Grabbing an access token...\n";

$oauth->setToken($request_token["oauth_token"], $request_token["oauth_token_secret"]);
$access_token = $oauth->getAccessToken("http://services.digg.com/1.0/endpoint?method=oauth.getAccessToken", NULL, $verifier);

echo "Got an access token: " . $access_token["oauth_token"];

$oauth->setToken($access_token["oauth_token"], $access_token["oauth_token_secret"]);

$oauth->fetch("http://services.digg.com/1.0/endpoint?method=story.digg", array("story_id" => "21595036"));

$xml = simplexml_load_string($oauth->getLastResponse());

echo "http://digg.com/programming/PHP_OAuth_Manual has been dugg\n";

} catch (OAuthException $E) {
var_dump($E);
}

?>
