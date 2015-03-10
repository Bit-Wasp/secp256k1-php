/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2014 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_SECP256K1_H
#define PHP_SECP256K1_H

extern zend_module_entry secp256k1_module_entry;
#define phpext_secp256k1_ptr &secp256k1_module_entry

#define PHP_SECP256K1_VERSION "0.1.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#	define PHP_SECP256K1_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SECP256K1_API __attribute__ ((visibility("default")))
#else
#	define PHP_SECP256K1_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_FUNCTION(secp256k1_start);
PHP_FUNCTION(secp256k1_stop);

/*
  	Declare any global variables you may need between the BEGIN
	and END macros here:

ZEND_BEGIN_MODULE_GLOBALS(secp256k1)
	zend_long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(secp256k1)
*/

/* Always refer to the globals in your function as SECP256K1_G(variable).
   You are encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define SECP256K1_G(v) ZEND_TSRMG(secp256k1_globals_id, zend_secp256k1_globals *, v)
#ifdef COMPILE_DL_SECP256K1
ZEND_TSRMLS_CACHE_EXTERN();
#endif
#else
#define SECP256K1_G(v) (secp256k1_globals.v)
#endif

#endif	/* PHP_SECP256K1_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
