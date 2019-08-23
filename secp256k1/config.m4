dnl $Id$
dnl config.m4 for extension secp256k1

PHP_ARG_WITH([secp256k1],
  [for secp256k1 support],
  [AS_HELP_STRING([--with-secp256k1],
               [Include secp256k1 support])])
PHP_ARG_WITH([secp256k1-config],
  [whether to enable advanced module configuration],
  [AS_HELP_STRING([--with-secp256k1-config],
      [Enable advanced module configuation])],
  [no],
  [no])
PHP_ARG_WITH([module-recovery],
  [whether to build secp256k1 with recovery support],
  [AS_HELP_STRING([--with-module-recovery],
      [Include recovery support])],
  [no],
  [no])
PHP_ARG_WITH([module-ecdh],
  [whether to build secp256k1 with ecdh support],
  [AS_HELP_STRING([--with-module-ecdh],
      [Include ecdh support])],
  [no],
  [no])
PHP_ARG_WITH([module-schnorrsig],
  [whether to build secp256k1 with schnorrsig support],
  [AS_HELP_STRING([--with-module-schnorrsig],
      [Include schnorrsig support])],
  [no],
  [no])

if test "$PHP_SECP256K1" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-secp256k1 -> check with-path
  SEARCH_PATH="/usr/local /usr"     # you might want to change this
  SEARCH_FOR="/include/secp256k1.h"  # you most likely want to change this
  if test -r $WITH_SECP256K1/$SEARCH_FOR; then # path given as parameter
    SECP256K1_DIR=$PHP_SECP256K1
  else # search default path list
    AC_MSG_CHECKING([for secp256k1 files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        SECP256K1_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi
  
  if test -z "$SECP256K1_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall the secp256k1 distribution])
  fi

  dnl # --with-secp256k1 -> add include path
  PHP_ADD_INCLUDE($SECP256K1_DIR/include)

  dnl # --with-secp256k1 -> check for lib and symbol presence
  LIBNAME=secp256k1 # you may want to change this
  LIBSYMBOL=secp256k1_context_create # you most likely want to change this 

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $SECP256K1_DIR/$PHP_LIBDIR, SECP256K1_SHARED_LIBADD)
    AC_DEFINE(HAVE_SECP256K1LIB,1,[ ])
  ],[
     AC_MSG_ERROR([wrong secp256k1 lib version or lib not found])
  ],[
    -L$SECP256K1_DIR/$PHP_LIBDIR -lm
  ])

  if test "$PHP_SECP256K1_CONFIG" = "yes"; then
    if test "$PHP_MODULE_RECOVERY" = "yes"; then
      PHP_CHECK_LIBRARY($LIBNAME,secp256k1_ecdsa_recover,
      [
        AC_DEFINE(SECP256K1_MODULE_RECOVERY, 1, [ ])
      ],[
         AC_MSG_ERROR([missing libraries for secp256k1 recovery support])
      ],[
      ])
    fi

    if test "$PHP_MODULE_ECDH" = "yes"; then
      PHP_CHECK_LIBRARY($LIBNAME,secp256k1_ecdh,
      [
        AC_DEFINE(SECP256K1_MODULE_ECDH, 1, [ ])
      ],[
         AC_MSG_ERROR([missing libraries for secp256k1 ecdh support])
      ],[
      ])
    fi

    if test "$PHP_MODULE_SCHNORRSIG" = "yes"; then
      PHP_CHECK_LIBRARY($LIBNAME,secp256k1_schnorrsig_verify,
      [
        AC_DEFINE(SECP256K1_MODULE_SCHNORRSIG, 1, [ ])
      ],[
         AC_MSG_ERROR([missing libraries for secp256k1 recovery support])
      ],[])
    fi
  else
    AC_DEFINE(SECP256K1_MODULE_RECOVERY, 1, [ ])
    AC_DEFINE(SECP256K1_MODULE_ECDH, 1, [ ])
    AC_DEFINE(SECP256K1_MODULE_SCHNORRSIG, 1, [ ])
  fi

  PHP_SUBST(SECP256K1_SHARED_LIBADD)

  PHP_NEW_EXTENSION(secp256k1, secp256k1.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
