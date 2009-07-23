--TEST--
OAuth getRequestToken
--SKIPIF--
<?php 
require 'skip.inc';
skip_if_not_php_major(5);
skip_without_bug('44603');
require 'server.inc';
http_server_skipif('tcp://127.0.0.1:12342');
?>
--FILE--
<?php
require 'server.inc';

$x = new OAuth('1234','1234');
$x->setRequestEngine(OAUTH_REQENGINE_STREAMS);

$pid = http_server("tcp://127.0.0.1:12342", array(
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
), $output);

$x->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));

$x->setAuthType(OAUTH_AUTH_TYPE_FORM);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));

$x->setAuthType(OAUTH_AUTH_TYPE_URI);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));

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
array(2) {
  ["oauth_token"]=>
  string(4) "1234"
  ["oauth_token_secret"]=>
  string(4) "4567"
}
array(2) {
  ["oauth_token"]=>
  string(4) "1234"
  ["oauth_token_secret"]=>
  string(4) "4567"
}
string(%d) "GET /test HTTP/%f
Authorization: OAuth oauth_consumer_key="1234",oauth_signature_method="HMAC-SHA1",oauth_nonce="%s.%d",oauth_timestamp="%d",oauth_version="1.0",oauth_signature="%s"
Host: 127.0.0.1:12342

POST /test HTTP/%f
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1:12342
Content-Length: %d

oauth_consumer_key=1234&oauth_signature_method=HMAC-SHA1&oauth_nonce=%s.%d&oauth_timestamp=%d&oauth_version=1.0&oauth_signature=%s
GET /test?oauth_consumer_key=1234&oauth_signature_method=HMAC-SHA1&oauth_nonce=%s.%d&oauth_timestamp=%d&oauth_version=1.0&oauth_signature=%s HTTP/%f
Host: 127.0.0.1:12342

"
