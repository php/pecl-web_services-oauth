# Changelog

## 2.0.12 - 2026-04-07

* Fix segfault when OAuthProvider callback handler throws an exception (issue #27)
* Replace deprecated cURL `curl_formadd()` API with MIME API for multipart form uploads (issue #37)
* Fix double free in OAuth destructor for `headers_in` and `headers_out`
* Fix dangling pointers in multipart file/param storage by copying strings
* Fix invalid free of shifted multipart param pointers
* Fix memory leak in OAuthProvider auth header parsing
* Fix memory leak in OAuthProvider callback registration on invalid callback type
* Add multipart array cleanup in destructor for exception safety
* Add GitHub Actions CI for PHP 8.1-8.5
* Add PIE support (composer.json, package name pecl/oauth)

## 2.0.10 - 2025-10-09

* Fix PHP 8.5 compatibility

## 2.0.9 - 2024-10-08

* Fix PHP 8.3 deprecations
* Fix PHP 8.4 compatibility

## 2.0.8 - 2022-04-21

* Fix sporadic segfault in checkOAuthRequest

## 2.0.7 - 2020-09-18

* PHP 8 compatibility

## 2.0.6 - 2020-09-09

* Fix github issue #14 (Fixes for 7.3/7.4 and opcache)
* Fix PHP 7.4 compatibility of object handler
* Fix memory leaks in OAuthProvider
* Fix crash in OAuthProvider handler registration methods due to unconditional addref
* Fix crash in OAuth::fetch() due to modifying hash tables with a refcount>1

## 2.0.5 - 2020-02-06

* Fix config.w32 (cmb)
* Fix 7.3 segfault (rlerdorf)
* Replace uint/uint32_t, ulong/zend_ulong (Jan-E)
* Handle cases where a passed in array might be a const (keyurdg)
* Fix configure for recent cURL versions (cmb)
* Bug #76722 cURL library headers not recognized on Debian 9 (js361014)

## 2.0.4 - 2019-12-02

* Fix php_pcre_match_impl call in 7.4+ (Remi)

## 2.0.3 - 2018-09-30

* Use _ex versions to avoid SIGABRT during use of hash functions in 7.2+ (Derick Rethans)

## 2.0.2 - 2018-06-28

* Fix bug #74163: Segfault in oauth_compare_value
* Fix bug #73434: Null byte at end of array keys in getLastResponseInfo
* Fix compatibility with PHP 7.3

## 2.0.1 - 2016-03-11

* Fix multiple segfaults (kgovande, rlerdorf)

## 2.0.0 - 2016-01-02

* PHP 7 Support
* Bug #67658: configure does not detect missing pcre.h
* Bug #67665: update fetch to accept 20X HTTP ranges
* Bug #67883: check SERVER[REDIRECT_HTTP_AUTHORIZATION] for the Authorization header
