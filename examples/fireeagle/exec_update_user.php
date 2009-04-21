<?php
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_FORM);

	$access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/access_token_resp"));

	$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);
    
    /* https://fireeagle.yahoo.net/developer/documentation/updating */
	$arrayResp = $o->fetch("https://fireeagle.yahooapis.com/api/0.1/update",array("postal" => "95054"));
    echo $o->getLastResponse();
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
