dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(oauth, for oauth support,
[  --enable-oauth          Include oauth support])

if test "$PHP_OAUTH" != "no"; then
  PHP_SUBST(OAUTH_SHARED_LIBADD)

  PHP_NEW_EXTENSION(oauth, oauth.c provider.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

dnl  PHP_ADD_EXTENSION_DEP(oauth, curl)
  PHP_ADD_EXTENSION_DEP(oauth, hash)
fi
