--TEST--
OauthProvider tokenHandler/callTokenHandler
--FILE--
<?php
require 'oauth.inc';

function tokenHandler($provider) {
	echo 'tokenHandler called' . PHP_EOL;
}

try {
	$provider = new OAuthProvider(creationParams());
	$provider->tokenHandler('tokenHandler');
	$provider->callTokenHandler();
} catch (OAuthException $E) {
	echo OAuthProvider::reportProblem($E);
}

--EXPECT--
tokenHandler called
