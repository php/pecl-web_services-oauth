<?php

if (!defined('PHP_MAJOR_VERSION')) {
	list($major,$minor,$release) = split('[.-]', PHP_VERSION);
	define('PHP_MAJOR_VERSION', $major);
	define('PHP_MINOR_VERSION', $minor);
	define('PHP_RELEASE_VERSION', $release);
}

function skip_if_not_php_major($version)
{
	if (PHP_MAJOR_VERSION!=$version) {
		die("skip Only for PHP $version");
	}
}

function skip_of_not_at_least_php_major($version)
{
	if (PHP_MAJOR_VERSION<$version) {
		die("skip Only from PHP $version onwards");
	}
}

function skip_if_php_major($version)
{
	if (PHP_MAJOR_VERSION==$version) {
		die("skip Not for PHP $version");
	}
}

function skip_if_not_ext($ext)
{
	if (!extension_loaded($ext)) {
		die("skip $ext not loaded");
	}
}

function skip_if_not_constant($constant)
{
	if (!defined($constant)) {
		die("skip $constant not defined");
	}
}

function has_bug($bugid)
{
	switch ($bugid) {
		case '44603':
			// >= 5.1.0 && < 5.2.6
			return (PHP_MINOR_VERSION==1 || (PHP_MINOR_VERSION==2 && PHP_RELEASE_VERSION<6));
	}
	return false;
}

function skip_without_bug($bugid)
{
	if (!has_bug($bugid)) {
		die('skip Only for bug #'.$bugid);
	}
}

function skip_with_bug($bugid)
{
	if (has_bug($bugid)) {
		die('skip Not for bug #'.$bugid);
	}
}

?>
