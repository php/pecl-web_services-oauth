--TEST--
OAuth getRequestToken
--SKIPIF--
<?php
require 'skip.inc';
skip_of_not_at_least_php_major(6);
require 'server_php6.inc';
http_server_skipif('tcp://127.0.0.1:12342');
?>
--FILE--
<?php
require 'server_php6.inc';

$x = new OAuth('1234','1234');
$x->setRequestEngine(OAUTH_REQENGINE_STREAMS);

$pid = http_server("tcp://127.0.0.1:12342", array(
	b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
	b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
	b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
), $output);

echo "-- using authorization --\n";
$x->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));

echo "-- using form --\n";
$x->setAuthType(OAUTH_AUTH_TYPE_FORM);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));

echo "-- using uri --\n";
$x->setAuthType(OAUTH_AUTH_TYPE_URI);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));

fseek($output, 0, SEEK_SET);
var_dump(stream_get_contents($output));

http_server_kill($pid);

?>
--EXPECTF--
-- using authorization --
array(2) {
  [%u|b%"oauth_token"]=>
  %unicode|string%(4) "1234"
  [%u|b%"oauth_token_secret"]=>
  %unicode|string%(4) "4567"
}
-- using form --
array(2) {
  [%u|b%"oauth_token"]=>
  %unicode|string%(4) "1234"
  [%u|b%"oauth_token_secret"]=>
  %unicode|string%(4) "4567"
}
-- using uri --
array(2) {
  [%u|b%"oauth_token"]=>
  %unicode|string%(4) "1234"
  [%u|b%"oauth_token_secret"]=>
  %unicode|string%(4) "4567"
}
string(%d) "GET /test HTTP/%f
Host: 127.0.0.1:12342
Authorization: OAuth oauth_consumer_key="1234",oauth_signature_method="HMAC-SHA1",oauth_nonce="%s.%d",oauth_timestamp="%d",oauth_version="1.0",oauth_signature="%s"

POST /test HTTP/%f
Host: 127.0.0.1:12342
Content-Length: %d
Content-Type: application/x-www-form-urlencoded

oauth_consumer_key=1234&oauth_signature_method=HMAC-SHA1&oauth_nonce=%s.%d&oauth_timestamp=%d&oauth_version=1.0&oauth_signature=%s
GET /test?oauth_consumer_key=1234&oauth_signature_method=HMAC-SHA1&oauth_nonce=%s.%d&oauth_timestamp=%d&oauth_version=1.0&oauth_signature=%s HTTP/%f
Host: 127.0.0.1:12342

"
