<?php

include("constants.php");

try {
	$oauth = new OAuth(TWITTER_CONSUMER_KEY,TWITTER_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);

	/* do *not* use the next call for production environments */
    $oauth->disableSSLChecks();
    /* Uncomment either of the lines below to get the debugInfo member populated in $oauth */
    //$oauth->debug = 1;
    //$oauth->enableDebug();

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

    printf("Updating the status via %s\n",TWITTER_UPDATE_STATUS_API);
    $oauth->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

	$api_args = array("status" => "'hi' from pecl/oauth", "empty_param" => NULL);

    $oauth->fetch(TWITTER_UPDATE_STATUS_API, $api_args, OAUTH_HTTP_METHOD_POST, array("User-Agent" => "pecl/oauth"));

    if(!empty($oauth->debug)) {
        print_r($oauth->debugInfo);
    }

    /* from this point on OAuth is over, now handling the JSON response is in order */
    $json = json_decode($oauth->getLastResponse());
    printf("JSON Result: %s\n",print_r($json,true));

} catch(OAuthException $E) {
    print_r($E);
}

?>
