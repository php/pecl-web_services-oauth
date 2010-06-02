<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);
	$request_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/request_token_resp"));
	$o->setToken($request_token_info["oauth_token"],$request_token_info["oauth_token_secret"]);
	$arrayResp = $o->getAccessToken("https://www.google.com/accounts/OAuthGetAccessToken");
	file_put_contents(OAUTH_TMP_DIR . "/access_token_resp",serialize($arrayResp));
	echo "Finished getting the access token!\n";
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
