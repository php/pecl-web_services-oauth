--TEST--
PECL oauth: Bug #64308 (Protocol and host name not lowercased when generating signature base string)
--SKIPIF--
<?php # vim:ft=php
if (!extension_loaded('oauth')) die('skip');
?>
--FILE--
<?php
echo oauth_get_sbs('GET', 'HTTP://SimonWpt.trovebox.com/hello.json').PHP_EOL;
?>
--EXPECT--
GET&http%3A%2F%2Fsimonwpt.trovebox.com%2Fhello.json&
