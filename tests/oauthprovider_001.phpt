--TEST--
OauthProvider Creation
--FILE--
<?php
$provider = new OAuthProvider(['foo' => 'bar']);
var_dump($provider);

--EXPECT--
object(OAuthProvider)#1 (12) {
  ["consumer_key"]=>
  NULL
  ["consumer_secret"]=>
  NULL
  ["signature"]=>
  NULL
  ["signature_method"]=>
  NULL
  ["token"]=>
  NULL
  ["token_secret"]=>
  NULL
  ["nonce"]=>
  NULL
  ["timestamp"]=>
  NULL
  ["version"]=>
  NULL
  ["callback"]=>
  NULL
  ["verifier"]=>
  NULL
  ["request_token_endpoint"]=>
  bool(false)
}
