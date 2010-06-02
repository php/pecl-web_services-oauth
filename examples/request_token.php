<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);
    
    $arrayResp = $o->getRequestToken("https://www.foo.tld/oauth/requestToken");

	file_put_contents(OAUTH_TMP_DIR ."/request_token_resp",serialize($arrayResp));
    
    /* note: on the redirect there is no need to pass anything other than the oauth_token parameter */
	header("Location: https://www.foo.tld/oauth/authorize?oauth_token={$arrayResp["oauth_token"]}");
} catch(OAuthException $E) {
	print_r($E);
	echo "Response: ". $E->lastResponse . "\n";
}
