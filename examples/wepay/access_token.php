<?php
require './config.inc.php';
try {
	$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);

// Fetch the request token and secret obtained in step 1 (request_token.php)
	$request_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/wepay_request_token_resp"));
	$o->setToken($request_token_info["oauth_token"],$request_token_info["oauth_token_secret"]);

// This next step is a bit odd - it is because WePay is an OAuth 1.0a web service which requires a verifier in the
// callback from the user authorizing the request token.  In a real OAuth application you would, of course, capture
// this verifier with your own callback endpoint, but in order for this example script to work, we wrote a stub
// callback endpoint which saves the verifier and lets us fetch it from here.

	$vdata = json_decode(file_get_contents("http://progphp.com/oauth/".urlencode($request_token_info["oauth_token"])));

// Exchange the authorized request token by sending it to WePay's access_token endpoint along with the verifier

	$arrayResp = $o->getAccessToken("https://wepayapi.com/v1/oauth/access_token", NULL, $vdata->verifier);

// And we store this access token which we can use from now on to execute API calls against the WePay web API
	file_put_contents(OAUTH_TMP_DIR . "/wepay_access_token_resp",serialize($arrayResp));
	echo "Finished getting the access token!\n";
} catch(OAuthException $E) {
	echo "Response: ". $E->lastResponse . "\n";
}
