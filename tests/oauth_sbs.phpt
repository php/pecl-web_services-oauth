--TEST--
OAuth SBS function
--FILE--
<?php

echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/'),"\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/', array()),"\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',''),"\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',array('test'=>'hello')),"\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/?test=hi',array('test'=>'hello')),"\n";

?>
--EXPECTF--
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&

Warning: oauth_get_sbs() expects parameter 3 to be array, string given in %s

GET&http%3A%2F%2F127.0.0.1%3A12342%2F&test%3Dhello
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&test%3Dhi
