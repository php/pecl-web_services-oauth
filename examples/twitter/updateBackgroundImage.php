<?php

include("constants.php");

try {
	$oauth = new OAuth(TWITTER_CONSUMER_KEY,TWITTER_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);

	/* Uncomment the line below to get lots of debug */
	$oauth->enableDebug();

	/* multipart only works with the cURL engine at the moment */
	$oauth->setRequestEngine(OAUTH_REQENGINE_CURL);

	$request_token_info = $oauth->getRequestToken(TWITTER_REQUEST_TOKEN_URL);

	printf("I think I got a valid request token, navigate your www client to:\n\n%s?oauth_token=%s\n\nOnce you finish authorizing, hit ENTER or INTERRUPT to exit\n\n", TWITTER_AUTHORIZE_URL, $request_token_info["oauth_token"]);

	$in = fopen("php://stdin", "r");
	fgets($in, 255);

	printf("Grabbing an access token...\n");

	/* grab the access token, which is your persistent token which you use for future requests */
	$oauth->setToken($request_token_info["oauth_token"],$request_token_info["oauth_token_secret"]);
	$access_token_info = $oauth->getAccessToken(TWITTER_ACCESS_TOKEN_URL);

	printf("Access token: %s\n",$access_token_info["oauth_token"]);
	printf("Access token secret: %s\n",$access_token_info["oauth_token_secret"]);

	$oauth->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

	printf("Sending the background image...\n");
	$oauth->fetch(TWITTER_UPDATE_PROFILE_BG_API, array("tile" => "true", "@image" => "@". dirname(__FILE__) ."/php.jpg;filename=php.jpg;type=image/jpg"), OAUTH_HTTP_METHOD_POST);

	/* from this point on OAuth is over, now handling the JSON response is in order */
	$res = json_decode($oauth->getLastResponse());
	printf("Twitter background image URL: %s\n", $res->profile_background_image_url);

} catch(OAuthException $E) {
	print_r($E);
}

?>
