dnl $Id$
dnl config.m4 for extension secp256k1

PHP_ARG_WITH(secp256k1, for secp256k1 support,
dnl Make sure that the comment is aligned:
[  --with-secp256k1             Include secp256k1 support])

if test "$PHP_SECP256K1" != "no"; then
  dnl Write more examples of tests her

  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

  dnl system libsecp256k1, depends on libsecp256k1
  AC_MSG_CHECKING(for libsecp256k1)

  if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists libsecp256k1; then
    if $PKG_CONFIG libsecp256k1 --atleast-version 0.1; then
      LIBSECP256K1_CFLAGS=`$PKG_CONFIG libsecp256k1 --cflags`
      LIBSECP256K1_LIBDIR=`$PKG_CONFIG libsecp256k1 --variable=libdir`
      LIBSECP256K1_VERSION=`$PKG_CONFIG libsecp256k1 --modversion`
      AC_MSG_RESULT(from pkgconfig: version $LIBSECP256K1_VERSION found in $LIBSECP256K1_LIBDIR)

    else
      AC_MSG_ERROR(system libsecp2561 must be upgraded to version >= 0.11)
    fi

    PHP_CHECK_LIBRARY(secp256k1, secp256k1_context_create,
    [
      PHP_ADD_LIBRARY_WITH_PATH(secp256k1, $LIBSECP256K1_LIBDIR, SECP256K1_SHARED_LIBADD)
      AC_DEFINE(HAVE_LIBSECP256K1,1,[ ])
      AC_DEFINE(HAVE_SECP256K1,1,[ ])
    ], [
      AC_MSG_ERROR(could not find usable libsecp256k1)
    ], [
      -L$LIBSECP256K1_LIBDIR
    ])

    PHP_SUBST(SECP256K1_SHARED_LIBADD)
    PHP_NEW_EXTENSION(secp256k1, secp256k1.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)

  else

    PHP_SECP256K1_SOURCES="$PHP_SECP256K1_SOURCES secp256k1/src/secp256k1.c  "

    AC_DEFINE(HAVE_SECP256K1,1,[ ])
    PHP_NEW_EXTENSION(secp256k1, secp256k1.c $PHP_SECP256K1_SOURCES, $ext_shared,, -lsecp256k1 -lgmp)
    PHP_ADD_INCLUDE([$ext_srcdir/secp256k1])
    PHP_ADD_INCLUDE([$ext_srcdir/secp256k1/include])
    PHP_ADD_BUILD_DIR($ext_builddir/secp256k1/src, 1)
    PHP_SUBST(SECP256K1_SHARED_LIBADD)

  fi

fi
