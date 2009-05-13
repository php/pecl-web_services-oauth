dnl
dnl $Id$
dnl

PHP_ARG_WITH(oauth, for oauth support,
[  --with-oauth		Include oauth support])

if test "$PHP_OAUTH" != "no"; then
  PHP_SUBST(OAUTH_SHARED_LIBADD)

  PHP_CHECK_LIBRARY(curl,curl_easy_perform,[
    AC_DEFINE(OAUTH_HAVE_CURL,1,[ Define to 1 if you have curl. ])
    PHP_ADD_LIBRARY(curl,,OAUTH_SHARED_LIBADD)
  ],[
  ])

  PHP_NEW_EXTENSION(oauth, oauth.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  PHP_ADD_EXTENSION_DEP(oauth, curl)
  PHP_ADD_EXTENSION_DEP(oauth, hash)
fi
