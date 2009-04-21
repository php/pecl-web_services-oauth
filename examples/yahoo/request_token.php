<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);
	$arrayResp = $o->getRequestToken("https://api.login.yahoo.com/oauth/v2/get_request_token");
	file_put_contents(OAUTH_TMP_DIR . "/request_token_resp",serialize($arrayResp));
	$authorizeUrl = $arrayResp["xoauth_request_auth_url"];
	if(PHP_SAPI=="cli") {
		echo "Navigate your http client to: {$authorizeUrl}\n";
	} else {
		header("Location: {$authorizeUrl}");
	}
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
