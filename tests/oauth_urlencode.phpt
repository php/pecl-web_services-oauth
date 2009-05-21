--TEST--
OAuth urlencode
--FILE--
<?php

echo oauth_urlencode('http://www.example.com'),"\n";
echo oauth_urlencode('http://www.example.com/~user'),"\n";

?>
--EXPECTF--
http%3A%2F%2Fwww.example.com
http%3A%2F%2Fwww.example.com%2F~user
