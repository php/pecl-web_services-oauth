dnl
dnl $Id$
dnl

PHP_ARG_WITH(oauth, for oauth support,
[  --with-oauth		Include oauth support])

PHP_SUBST(OAUTH_SHARED_LIBADD)

PHP_ADD_LIBRARY(curl,,OAUTH_SHARED_LIBADD)

if test "$PHP_SIMPLEOAUTH" != "no"; then
  PHP_NEW_EXTENSION(oauth, oauth.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g -DCOMPILE_DL_OAUTH"
fi

PHP_ADD_EXTENSION_DEP(oauth, curl)
PHP_ADD_EXTENSION_DEP(oauth, hash)

