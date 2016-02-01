--TEST--
OauthProvider isRequestTokenEndpoint
--FILE--
<?php
require 'oauth.inc';

try {
	$provider = new OAuthProvider(creationParams());
	$provider->isRequestTokenEndpoint(true);
	var_dump($provider->request_token_endpoint);
} catch (OAuthException $E) {
	echo OAuthProvider::reportProblem($E);
}

--EXPECT--
bool(true)
