<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);
	$arrayResp = $o->getRequestToken("http://api.netflix.com/oauth/request_token");
	file_put_contents(OAUTH_TMP_DIR . "/request_token_resp",serialize($arrayResp));
	$authorizeUrl = $arrayResp["login_url"] . "&oauth_consumer_key=" . OAUTH_CONSUMER_KEY . "&application_name=" . $arrayResp["application_name"];
	if(PHP_SAPI=="cli") {
		echo "Navigate your http client to: {$authorizeUrl}\n";
	} else {
		header("Location: {$authorizeUrl}");
	}
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
