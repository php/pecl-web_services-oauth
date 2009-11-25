--TEST--
OAuth SBS function
--FILE--
<?php

echo "-- only two parameters --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/'),"\n";
echo "-- using empty array --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/', array()),"\n";
echo "-- using string instead of array --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',''),"\n";
echo "-- using numeric keys masked as a string --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',array('1'=>'hello')),"\n";
echo "-- using string keys --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',array('test'=>'hello')),"\n";
echo "-- using same var in url and params --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/?test=hi',array('test'=>'hello')),"\n";
echo "-- using null inside params --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',array('test'=>null)),"\n";
echo "-- putting oauth_signature inside by mistake --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/',array('oauth_signature'=>'hello world')),"\n";
echo "-- merging url query and extra params --\n";
echo oauth_get_sbs('GET', 'http://127.0.0.1:12342/script?arg1=1',array('arg2' => '2')),"\n";

?>
--EXPECTF--
-- only two parameters --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&
-- using empty array --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&
-- using string instead of array --

Warning: oauth_get_sbs() expects parameter 3 to be array,%sstring given in %s

-- using numeric keys masked as a string --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&1%3Dhello
-- using string keys --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&test%3Dhello
-- using same var in url and params --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&test%3Dhi
-- using null inside params --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&test%3D
-- putting oauth_signature inside by mistake --
GET&http%3A%2F%2F127.0.0.1%3A12342%2F&
-- merging url query and extra params --
GET&http%3A%2F%2F127.0.0.1%3A12342%2Fscript&arg1%3D1%26arg2%3D2
