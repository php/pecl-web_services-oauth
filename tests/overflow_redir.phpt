--TEST--
OAuth Overflow in header redirect
--SKIPIF--
<?php

require 'skip.inc';
skip_if_not_constant('OAUTH_REQENGINE_CURL');
require 'server.inc';
http_server_skipif('tcp://127.0.0.1:12342');

?>
--FILE--
<?php
require 'server.inc';

$x = new OAuth('1234','1234');
$x->setRequestEngine(OAUTH_REQENGINE_CURL);

$pid = http_server("tcp://127.0.0.1:12342", array(
	"HTTP/1.0 302 Found\r\nLocation: http://127.0.0.1:12342/" . str_repeat('a', 512) . "bbb\r\n\r\n",
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
), $output);

try {
	$x->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);
	var_dump($x->getRequestToken('http://127.0.0.1:12342/test', null, 'GET'));
} catch (Exception $e) {
	var_dump($x->debugInfo);
}
fseek($output, 0, SEEK_SET);
var_dump(stream_get_contents($output));

http_server_kill($pid);

?>
--EXPECTF--
array(2) {
  ["oauth_token"]=>
  string(4) "1234"
  ["oauth_token_secret"]=>
  string(4) "4567"
}
string(%d) "GET /test HTTP/%f
User-Agent: PECL-OAuth/%f%s
Host: 127.0.0.1:12342
Accept: */*
Authorization: OAuth oauth_consumer_key="1234",oauth_signature_method="HMAC-SHA1",oauth_nonce="%s.%d",oauth_timestamp="%d",oauth_version="1.0",oauth_signature="%s"

GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/%f
User-Agent: PECL-OAuth/%f%s
Host: 127.0.0.1:12342
Accept: */*
Authorization: OAuth oauth_consumer_key="1234",oauth_signature_method="HMAC-SHA1",oauth_nonce="%s.%d",oauth_timestamp="%d",oauth_version="1.0",oauth_signature="%s"

"
