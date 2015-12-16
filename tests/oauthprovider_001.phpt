--TEST--
OauthProvider Creation
--FILE--
<?php
$provider = new OAuthProvider(['foo' => 'bar']);
var_dump($provider);

--EXPECT--
object(OAuthProvider)#1 (10) {
  ["consumer_key"]=>
  NULL
  ["consumer_secret"]=>
  NULL
  ["nonce"]=>
  NULL
  ["token"]=>
  NULL
  ["token_secret"]=>
  NULL
  ["timestamp"]=>
  NULL
  ["version"]=>
  NULL
  ["signature_method"]=>
  NULL
  ["callback"]=>
  NULL
  ["request_token_endpoint"]=>
  bool(false)
}
