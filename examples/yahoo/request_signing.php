<?php
/* the important difference here is that there is no user auth required, in other words, it is only for resources which do not need access to user access but need to be identified to the service provider */
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);
	$o->fetch("http://query.yahooapis.com/v1/yql?q=show%20tables&format=xml");
	$response_info = $o->getLastResponseInfo();
	header("Content-Type: {$response_info["content_type"]}");
	echo $o->getLastResponse();
} catch(Exception $E) {
	echo "Error: [".$E->getMessage()."]<br>\n";
	echo "Response: [".$E->lastResponse."]<br>\n";
	exit;
}
