<?php
require './config.inc.php';
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);

// Fetch the request token
	$arrayResp = $o->getRequestToken("https://wepayapi.com/v1/oauth/request_token");

// And save it 
	file_put_contents(OAUTH_TMP_DIR . "/wepay_request_token_resp",serialize($arrayResp));

// Get the authorizating URL that the user needs to click on to authorize the request token
	$authorizeUrl = $arrayResp["login_url"];
	if(PHP_SAPI=="cli") {
		echo "Point your Web browser at: {$authorizeUrl}\n";
	} else {
		header("Location: {$authorizeUrl}");
	}
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
