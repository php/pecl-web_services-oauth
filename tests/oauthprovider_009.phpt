--TEST--
OAuthProvider callback exception handling (issue #27)
--SKIPIF--
<?php
if (!extension_loaded("oauth")) die("skip oauth extension not loaded");
?>
--FILE--
<?php
$params = [
    "oauth_consumer_key" => "key",
    "oauth_signature" => "sig",
    "oauth_nonce" => "nonce",
    "oauth_timestamp" => "12345"
];

$p = new OAuthProvider($params);
$p->consumerHandler(function() { throw new RuntimeException("consumer exception"); });
$p->tokenHandler(function() { throw new RuntimeException("token exception"); });
$p->timestampNonceHandler(function() { throw new RuntimeException("nonce exception"); });

try {
    $p->callconsumerHandler();
} catch (RuntimeException $e) {
    echo $e->getMessage() . "\n";
}

try {
    $p->calltokenHandler();
} catch (RuntimeException $e) {
    echo $e->getMessage() . "\n";
}

try {
    $p->callTimestampNonceHandler();
} catch (RuntimeException $e) {
    echo $e->getMessage() . "\n";
}

echo "OK\n";
?>
--EXPECT--
consumer exception
token exception
nonce exception
OK
