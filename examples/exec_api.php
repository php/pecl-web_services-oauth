<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_FORM);

	$access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/access_token_resp"));
	$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);
    
	$arrayResp = $o->fetch("https://www.foo.tld/oauth/an_api_for_user_info",array("extra" => "arg(h)"));
    echo $o->getLastResponse();
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
