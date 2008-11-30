<?php

require 'config.inc.php';

try {
	$oauth = new OAuth(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
	$response = $oauth->getRequestToken('http://api.netflix.com/oauth/request_token');
	file_put_contents('/tmp/request_token_resp', serialize($response));
	$login = $response['login_url'];

	if (PHP_SAPI == 'cli') {
		echo "Navigate your http client to: {$login}\n";
	} else {
		header("Location: {$login}");
	}
} catch(OAuthException $e) {
	echo "Response: ". $e->lastResponse . "\n";
}
