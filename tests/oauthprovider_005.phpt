--TEST--
OauthProvider timestampNonceHandler/callTimestampNonceHandler
--FILE--
<?php
require 'oauth.inc';

function timestampNonceHandler($provider) {
	echo 'timestampNonceHandler called' . PHP_EOL;
}

try {
	$provider = new OAuthProvider(creationParams());
	$provider->timestampNonceHandler('timestampNonceHandler');
	$provider->callTimestampNonceHandler();
} catch (OAuthException $E) {
	echo OAuthProvider::reportProblem($E);
}

--EXPECT--
timestampNonceHandler called
