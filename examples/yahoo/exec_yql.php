<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);
	$access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/access_token_resp"));
	$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

	$query = rawurlencode("select * from social.profile where guid=me");
	$o->fetch("http://query.yahooapis.com/v1/yql?q=$query&format=xml");

	$response_info = $o->getLastResponseInfo();
	header("Content-Type: {$response_info["content_type"]}");
	echo $o->getLastResponse();
} catch(OAuthException $E) {
	echo "Exception caught!\n";
	echo "Response: ". $E->lastResponse . "\n";
}
