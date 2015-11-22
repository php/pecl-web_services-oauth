--TEST--
Oauth curl debug handler
--SKIPIF--
<?php
require 'skip.inc';
require 'server.inc';
http_server_skipif('tcp://127.0.0.1:12342');
skip_if_not_constant('OAUTH_REQENGINE_CURL');
?>
--FILE--
<?php
require 'server.inc';

$x = new OAuth('conskey', 'conssecret', OAUTH_SIG_METHOD_PLAINTEXT);
$x->setRequestEngine(OAUTH_REQENGINE_STREAMS);
$x->setTimestamp(12345);
$x->setNonce('testing');
$x->enableDebug();
$x->setRequestEngine(OAUTH_REQENGINE_CURL);

$pid = http_server("tcp://127.0.0.1:12342", array(
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
), $output);

$x->setAuthType(OAUTH_AUTH_TYPE_URI);
$x->getRequestToken('http://127.0.0.1:12342/test');

fseek($output, 0, SEEK_SET);
stream_get_contents($output);

var_dump(count($x->debugInfo));

http_server_kill($pid);

?>
--EXPECTF--
int(5)
