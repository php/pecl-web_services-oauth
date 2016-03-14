--TEST--
OauthProvider setParam addref segfault
--FILE--
<?php
require 'oauth.inc';

$provider = new OAuthProvider(['long_var' => 1]);
$provider->setParam('long_var', 2);
echo 'here';

--EXPECT--
here
