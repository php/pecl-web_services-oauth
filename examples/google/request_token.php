<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);

	/* Google scopes are in the following format: urlencoded(scope) urlencoded(scope) */
	$scopes = urlencode("http://www.google.com/calendar/feeds/") . "%20" . urlencode("http://www.blogger.com/feeds/");

	$arrayResp = $o->getRequestToken("https://www.google.com/accounts/OAuthGetRequestToken?scope={$scopes}");
	file_put_contents(OAUTH_TMP_DIR . "/request_token_resp",serialize($arrayResp));
	$authorizeUrl = "https://www.google.com/accounts/OAuthAuthorizeToken?oauth_token={$arrayResp["oauth_token"]}";
	if(PHP_SAPI=="cli") {
		echo "Navigate your http client to: {$authorizeUrl}\n";
	} else {
		header("Location: {$authorizeUrl}");
	}
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
