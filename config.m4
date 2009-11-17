dnl
dnl $Id$
dnl

PHP_ARG_WITH(oauth, for oauth support,
[  --with-oauth		Include oauth support])

if test "$PHP_OAUTH" != "no"; then
  PHP_SUBST(OAUTH_SHARED_LIBADD)

  PHP_NEW_EXTENSION(oauth, oauth.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

dnl  PHP_ADD_EXTENSION_DEP(oauth, curl)
  PHP_ADD_EXTENSION_DEP(oauth, hash)
fi
