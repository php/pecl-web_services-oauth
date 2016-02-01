--TEST--
OauthProvider consumerHandler/callConsumerHandler
--FILE--
<?php
require 'oauth.inc';

function consumerHandler($provider) {
	echo 'consumerHandler called' . PHP_EOL;
}

try {
	$provider = new OAuthProvider(creationParams());
	$provider->consumerHandler('consumerHandler');
	$provider->callConsumerHandler();
} catch (OAuthException $E) {
	echo OAuthProvider::reportProblem($E);
}

--EXPECT--
consumerHandler called
