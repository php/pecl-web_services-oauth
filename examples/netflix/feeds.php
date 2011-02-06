<?php
require("config.inc.php");

$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);
try {
	$access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/access_token_resp"));
	$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

	$feeds_url = "http://api.netflix.com/users/". oauth_urlencode($access_token_info["user_id"]) ."/feeds";
	$o->fetch($feeds_url);

	$response_info = $o->getLastResponseInfo();
	header("Content-Type: {$response_info["content_type"]}");
	echo $o->getLastResponse();
} catch(OAuthException $E) {
	echo "Exception caught!\n";
	echo "Response: ". $E->lastResponse . "\n";
    var_dump($E);
}
