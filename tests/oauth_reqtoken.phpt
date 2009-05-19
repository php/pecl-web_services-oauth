--TEST--
OAuth standard tests
--SKIPIF--
<?php require 'server.inc'; http_server_skipif('tcp://127.0.0.1:12342'); ?>
--FILE--
<?php
require 'server.inc';

$x = new OAuth('1234','1234');

$pid = http_server("tcp://127.0.0.1:12342", array(
	"data://text/plain,HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\noauth_token=1234&oauth_token_secret=4567",
), $output);
var_dump($x->getRequestToken('http://127.0.0.1:12342/test'));
http_server_kill($pid);

?>
--EXPECTF--
array(2) {
  ["oauth_token"]=>
  string(4) "1234"
  ["oauth_token_secret"]=>
  string(4) "4567"
}
