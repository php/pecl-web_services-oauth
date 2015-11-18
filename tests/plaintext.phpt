--TEST--
OAuth plaintext
--SKIPIF--
<?php
require 'skip.inc';
require 'server.inc';
http_server_skipif('tcp://127.0.0.1:12342');
?>
--FILE--
<?php
require 'server.inc';

$x = new OAuth('conskey', 'conssecret', OAUTH_SIG_METHOD_PLAINTEXT);
$x->setRequestEngine(OAUTH_REQENGINE_STREAMS);
$x->setTimestamp(12345);
$x->setNonce('testing');

$pid = http_server("tcp://127.0.0.1:12342", array(
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
), $output);

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
string(%d) "POST /test?oauth_consumer_key=conskey&oauth_signature_method=PLAINTEXT&oauth_nonce=testing&oauth_timestamp=12345&oauth_version=1.0&oauth_signature=conssecret%26 HTTP/1.0
Host: 127.0.0.1:12342
Connection: close

"
