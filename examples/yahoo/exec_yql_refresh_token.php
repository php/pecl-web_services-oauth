<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);
	$access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/access_token_resp"));
	$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

	/* the following bit refreshes the token using the session handle (http://wiki.oauth.net/ScalableOAuth) ... you don't need it unless your original access token is invalid but you'll need to audit this yourself, for example sakes we'll pretend it has expired. */
	if(!empty($access_token_info["oauth_session_handle"])) {
		$o->setAuthType(OAUTH_AUTH_TYPE_URI);

		$access_token_info = $o->getAccessToken("https://api.login.yahoo.com/oauth/v2/get_token",$access_token_info["oauth_session_handle"]);
		$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

		$o->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);
		file_put_contents(OAUTH_TMP_DIR . "/access_token_resp",serialize($access_token_info));
	}
    /* done refreshing access token, time to do some fetching! */
	
	$query = rawurlencode("select * from social.profile where guid=me");
	$o->fetch("http://query.yahooapis.com/v1/yql?q=$query&format=xml");

	$response_info = $o->getLastResponseInfo();
	header("Content-Type: {$response_info["content_type"]}");
	echo $o->getLastResponse();
} catch(OAuthException $E) {
	echo "Exception caught!\n";
	echo "Response: ". $E->lastResponse . "\n";
}
