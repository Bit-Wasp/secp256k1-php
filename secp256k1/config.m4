dnl $Id$
dnl config.m4 for extension secp256k1

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(secp256k1, for secp256k1 support,
dnl Make sure that the comment is aligned:
[  --with-secp256k1             Include secp256k1 support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(secp256k1, whether to enable secp256k1 support,
dnl Make sure that the comment is aligned:
dnl [  --enable-secp256k1           Enable secp256k1 support])

if test "$PHP_SECP256K1" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-secp256k1 -> check with-path
  SEARCH_PATH="/usr/local /usr"     # you might want to change this
  SEARCH_FOR="/include/secp256k1.h"  # you most likely want to change this
  if test -r $PHP_SECP256K1/$SEARCH_FOR; then # path given as parameter
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
  LIBSYMBOL=secp256k1_nonce_function_default # you most likely want to change this 

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $SECP256K1_DIR/$PHP_LIBDIR, SECP256K1_SHARED_LIBADD)
    AC_DEFINE(HAVE_SECP256K1LIB,1,[ ])
  ],[
     AC_MSG_ERROR([wrong secp256k1 lib version or lib not found])
  ],[
    -L$SECP256K1_DIR/$PHP_LIBDIR -lm
  ])
  
  PHP_SUBST(SECP256K1_SHARED_LIBADD)

  PHP_NEW_EXTENSION(secp256k1, secp256k1.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
