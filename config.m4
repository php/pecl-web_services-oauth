dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(oauth, for oauth support,
[  --enable-oauth          Include oauth support])

AC_ARG_WITH([curl],
    AS_HELP_STRING([--without-curl], [Ignore presence of cURL and disable it]))

if test "$PHP_OAUTH" != "no"; then
  PHP_SUBST(OAUTH_SHARED_LIBADD)

  PHP_NEW_EXTENSION(oauth, oauth.c provider.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  AC_CHECK_HEADER(pcre.h, , [AC_MSG_ERROR([Couldn't find pcre.h, try installing the libpcre development/headers package])])

  AS_IF([test "x$with_curl" != "xno"],
      [
        AC_MSG_CHECKING(for cURL in default path)
        have_curl=no
        for i in /usr/local /usr; do
          if test -r $i/include/curl/easy.h; then
            have_curl=yes
            CURL_DIR=$i
            AC_MSG_RESULT(found in $i)
            break
          fi
        done
      ],
      [have_curl=no])

  AS_IF([test "x$have_curl" = "xyes"],
      [
        PHP_ADD_LIBRARY(curl,,OAUTH_SHARED_LIBADD)
        AC_DEFINE(OAUTH_USE_CURL, 1, [Whether cURL is present and should be used])
      ],
      [AS_IF([test "x$with_curl" = "xyes"],
             [AC_MSG_ERROR([cURL requested but not found])
      ])
  ])

  PHP_ADD_EXTENSION_DEP(oauth, hash)
fi
