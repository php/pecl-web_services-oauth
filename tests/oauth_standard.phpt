--TEST--
OAuth Standard functions
--FILE--
<?php

echo "-- empty params --\n";
$x = new OAuth;
var_dump($x);
echo "-- one param --\n";
$x = new OAuth('');
var_dump($x);
echo "-- empty consumer key and secret --\n";
$x = null;
try {
	$x = new OAuth('', '');
} catch (Exception $e) {
	echo "EXCEPTION {$e->getCode()}: {$e->getMessage()}\n";
}
var_dump($x);
echo "-- empty consumer secret --\n";
try {
	$x = new OAuth('1234', '');
} catch (Exception $e) {
	echo "EXCEPTION {$e->getCode()}: {$e->getMessage()}\n";
}
var_dump($x);

echo "-- normal constructor --\n";
$x = new OAuth('1234', '5678');
var_dump($x);

echo "-- enable debug --\n";
$x->enableDebug();
var_dump($x->debug);

echo "-- disable debug --\n";
$x->disableDebug();
var_dump($x->debug);

try {
	echo "-- set version without parameters --\n";
	var_dump($x->setVersion());
} catch (Exception $e) {
	echo "EXCEPTION {$e->getCode()}: {$e->getMessage()}\n";
}
try {
	echo "-- set version with boolean --\n";
	var_dump($x->setVersion(true));
} catch (Exception $e) {
	echo "EXCEPTION {$e->getCode()}: {$e->getMessage()}\n";
}

try {
	echo "-- set version with empty string --\n";
	var_dump($x->setVersion(''));
} catch (Exception $e) {
	echo "EXCEPTION {$e->getCode()}: {$e->getMessage()}\n";
}

echo "-- set version to 1 --\n";
var_dump($x->setVersion('1'));

try {
	echo "-- set auth type to invalid type 99 --\n";
	var_dump($x->setAuthType(99));
} catch (Exception $e) {
	echo "EXCEPTION {$e->getCode()}: {$e->getMessage()}\n";
}

echo "-- generate a signature --\n";
var_dump(is_string($x->generateSignature('GET', 'http://www.friendface.com/foo', array('param' => 'value'))));

echo "-- set a timeout (100 ms) --\n";
var_dump($x->setTimeout(100));

echo "-- set an invalid timeout --\n";
try {
$x->setTimeout(-1);
} catch (Exception $E) {
echo "EXCEPTION {$E->getCode()}: {$E->getMessage()}\n";
}
?>
--EXPECTF--
-- empty params --

Warning: OAuth::__construct() expects at least 2 parameters, 0 given %s
object(OAuth)#1 (3) {
  ["debug"]=>
  int(0)
  ["sslChecks"]=>
  int(1)
  ["debugInfo"]=>
  string(0) ""
}
-- one param --

Warning: OAuth::__construct() expects at least 2 parameters, 1 given %s
object(OAuth)#2 (3) {
  ["debug"]=>
  int(0)
  ["sslChecks"]=>
  int(1)
  ["debugInfo"]=>
  string(0) ""
}
-- empty consumer key and secret --
EXCEPTION -1: The consumer key cannot be empty
NULL
-- empty consumer secret --
object(OAuth)#2 (3) {
  ["debug"]=>
  bool(false)
  ["sslChecks"]=>
  bool(false)
  ["debugInfo"]=>
  NULL
}
-- normal constructor --
object(OAuth)#3 (3) {
  ["debug"]=>
  bool(false)
  ["sslChecks"]=>
  bool(false)
  ["debugInfo"]=>
  NULL
}
-- enable debug --
bool(true)
-- disable debug --
bool(false)
-- set version without parameters --

Warning: OAuth::setVersion() expects exactly 1 parameter, 0 given %s
NULL
-- set version with boolean --
bool(true)
-- set version with empty string --
EXCEPTION 503: Invalid version
-- set version to 1 --
bool(true)
-- set auth type to invalid type 99 --
EXCEPTION 503: Invalid auth type
-- generate a signature --
bool(true)
-- set a timeout (100 ms) --
bool(true)
-- set an invalid timeout --
EXCEPTION 503: Invalid timeout
