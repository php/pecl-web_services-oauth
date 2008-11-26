<?php
/* the important difference here is that there is no user auth required, in other words, it is only for api's which do not require user auth 
 * (such as /recent and /lookup)
 */
require("config.inc.php");
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);

	/* fire eagle uses something called a general purpose token/secret for request signing, a setToken call will suffice to handle it */
	$o->setToken(GENERAL_PURPOSE_TOKEN,GENERAL_PURPOSE_TOKEN_SECRET);

	$o->fetch("https://fireeagle.yahooapis.com/api/0.1/recent.xml");

	$response_info = $o->getLastResponseInfo();
	header("Content-Type: {$response_info["content_type"]}");
	echo $o->getLastResponse();
} catch(Exception $E) {
	echo "Error: [".$E->errorMessage."]<br>\n";
	echo "Response: [".$E->lastResponse."]<br>\n";
	exit;
}
