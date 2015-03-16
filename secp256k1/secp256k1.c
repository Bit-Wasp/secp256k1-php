/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_string.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_secp256k1.h"

#include <secp256k1.h>

PHP_FUNCTION(secp256k1_start) {

    long mode;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
            &mode
            ) == FAILURE) {
        return;
    }

    secp256k1_start(mode);
}

PHP_FUNCTION(secp256k1_stop) {
    secp256k1_stop();
}

/**
 * Verify an ECDSA signature.
 *
 * Returns: 1: correct signature
 * 0: incorrect signature
 * -1: invalid public key
 * -2: invalid signature
 *
 * In: msg32: the 32-byte message hash being verified (cannot be NULL)
 * sig: the signature being verified (cannot be NULL)
 * pubkey: the public key to verify with (cannot be NULL)
 * Requires starting using SECP256K1_START_VERIFY.
 */
PHP_FUNCTION(secp256k1_ecdsa_verify) {
    secp256k1_start(SECP256K1_START_VERIFY);

    unsigned char *msg32 = (unsigned char *) 0;
    int msg32len;
    unsigned char *sig = (unsigned char *) 0;
    int siglen;
    unsigned char *pubkey = (unsigned char *) 0;
    int pubkeylen;
    zval **args[5];
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
            &msg32, &msg32len,
            &sig, &siglen,
            &pubkey, &pubkeylen
            ) == FAILURE)
        return;


    result = secp256k1_ecdsa_verify(msg32, sig, siglen, pubkey, pubkeylen);

    RETURN_LONG(result);
}

/** Create an ECDSA signature.
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, the private key was invalid, or there is not
 *              enough space in the signature (as indicated by siglen).
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In/Out:  siglen: pointer to an int with the length of sig, which will be updated
 *                   to contain the actual signature length (<=72). If 0 is returned, this will be
 *                   set to zero.
 *
 * The sig always has an s value in the lower half of the range (From 0x1
 * to 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
 * inclusive), unlike many other implementations.
 * With ECDSA a third-party can can forge a second distinct signature
 * of the same message given a single initial signature without knowing
 * the key by setting s to its additive inverse mod-order, 'flipping' the
 * sign of the random point R which is not included in the signature.
 * Since the forgery is of the same message this isn't universally
 * problematic, but in systems where message malleability or uniqueness
 * of signatures is important this can cause issues.  This forgery can be
 * blocked by all verifiers forcing signers to use a canonical form. The
 * lower-S form reduces the size of signatures slightly on average when
 * variable length encodings (such as DER) are used and is cheap to
 * verify, making it a good choice. Security of always using lower-S is
 * assured because anyone can trivially modify a signature after the
 * fact to enforce this property.  Adjusting it inside the signing
 * function avoids the need to re-serialize or have curve specific
 * constants outside of the library.  By always using a canonical form
 * even in applications where it isn't needed it becomes possible to
 * impose a requirement later if a need is discovered.
 * No other forms of ECDSA malleability are known and none seem likely,
 * but there is no formal proof that ECDSA, even with this additional
 * restriction, is free of other malleability.  Commonly used serialization
 * schemes will also accept various non-unique encodings, so care should
 * be taken when this property is required for an application.
 */
PHP_FUNCTION(secp256k1_ecdsa_sign) {
    secp256k1_start(SECP256K1_START_SIGN);
    unsigned char *seckey = NULL;
    unsigned char *msg32 = NULL;
    zval *signature = NULL;
    int msg32len, seckeylen;
    zval *signatureLen;

    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "szzs", &msg32, &msg32len, &signature, &signatureLen, &seckey, &seckeylen) == FAILURE) {
       return;
    }

    unsigned char *newsig = Z_STRVAL_P(signature);
    int newsiglen;

    result = secp256k1_ecdsa_sign(msg32, newsig, &newsiglen, seckey, NULL, NULL);
    if (result) {
       newsig[newsiglen] = '\0';
       ZVAL_STRING(signature, newsig, 1);
       ZVAL_LONG(signatureLen, newsiglen);
    }
    RETURN_LONG(result);
}

/** Verify an ECDSA secret key.
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
PHP_FUNCTION(secp256k1_ec_seckey_verify) {
    unsigned char *seckey;
    int seckeylen;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
            &seckey, &seckeylen
            ) == FAILURE) {
        return;
    }

    result = secp256k1_ec_seckey_verify(seckey);
    RETURN_LONG(result);
}

/** Just validate a public key.
 *  Returns: 1: valid public key
 *           0: invalid public key
 *  In:      pubkey:    pointer to a 33-byte or 65-byte public key (cannot be NULL).
 *           pubkeylen: length of pubkey
 */
PHP_FUNCTION(secp256k1_ec_pubkey_verify) {
    secp256k1_start(SECP256K1_START_SIGN);

    unsigned char *pubkey;
    int pubkeylen;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
            &pubkey, &pubkeylen
            ) == FAILURE) {
        return;
    }

    result = secp256k1_ec_pubkey_verify(pubkey, pubkeylen);
    RETURN_LONG(result);
}

PHP_FUNCTION(secp256k1_test_by_reference) {
    zval *parameter;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &parameter) == FAILURE)
        return;

    /* make changes to the parameter */
    ZVAL_LONG(parameter, 10);

    RETURN_TRUE;
}

/** Compute the public key for a secret key.
 *  In:     compressed: whether the computed public key should be compressed
 *          seckey:     pointer to a 32-byte private key (cannot be NULL)
 *  Out:    pubkey:     pointer to a 33-byte (if compressed) or 65-byte (if uncompressed)
 *                      area to store the public key (cannot be NULL)
 *          pubkeylen:  pointer to int that will be updated to contains the pubkey's
 *                      length (cannot be NULL)
 *  Returns: 1: secret was valid, public key stores
 *           0: secret was invalid, try again.
 */
PHP_FUNCTION(secp256k1_ec_pubkey_create) {
    secp256k1_start(SECP256K1_START_SIGN);

    zval *pubkey;
    zval *pubkeylen;
    unsigned char newpubkey[65];
    int newpubkeylen;
    unsigned char *seckey;
    int seckeylen, compressed, result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzsb",
            &pubkey,
            &pubkeylen,
            &seckey, &seckeylen,
            &compressed
            ) == FAILURE)
        return;

    result = secp256k1_ec_pubkey_create(newpubkey, &newpubkeylen, (unsigned char const *) seckey, (int) compressed);
    if (result) {
        newpubkey[newpubkeylen] = '\0';
        ZVAL_STRING(pubkey, newpubkey, 1);
        ZVAL_LONG(pubkeylen, newpubkeylen);
    }

    RETURN_LONG(result);
}

/** Decompress a public key.
 * In/Out: pubkey:    pointer to a 65-byte array to put the decompressed public key.
                      It must contain a 33-byte or 65-byte public key already (cannot be NULL)
 *         pubkeylen: pointer to the size of the public key pointed to by pubkey (cannot be NULL)
                      It will be updated to reflect the new size.
 * Returns: 0 if the passed public key was invalid, 1 otherwise. If 1 is returned, the
            pubkey is replaced with its decompressed version.
 */
PHP_FUNCTION(secp256k1_ec_pubkey_decompress) {
    secp256k1_start(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);

    zval *pubkey;
    zval *pubkeylen;
    unsigned char* newpubkey;
    int newpubkeylen = 33;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz",
            &pubkey,
            &pubkeylen
            ) == FAILURE) {
        return;
    }

    newpubkey = Z_STRVAL_P(pubkey);
    newpubkeylen = Z_LVAL_P(pubkeylen);
    result = secp256k1_ec_pubkey_decompress(newpubkey, &newpubkeylen);
    if (result == 1) {
        newpubkey[newpubkeylen] = '\0';
        ZVAL_STRING(pubkey, newpubkey, 1);
        ZVAL_LONG(pubkeylen, newpubkeylen);
    }
    RETURN_LONG(result);
}

/** Import a private key in DER dormat. */
PHP_FUNCTION (secp256k1_ec_privkey_import) {
    unsigned char *privkey;
    unsigned char *newseckey;
    int privkeylen, result;
    zval *seckey;
    long compressed;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zsl",
            seckey,
            &privkey,
            &privkeylen,
            compressed
            ) == FAILURE) {
        return;
    }
    result = secp256k1_ec_privkey_import(newseckey, privkey, compressed);
    if (result) {
        newseckey[33] = '\0';
        ZVAL_STRING(seckey, newseckey, 1);
    }
    RETURN_LONG(result);
}

/** Export a private key in DER format. */
PHP_FUNCTION (secp256k1_ec_privkey_export) {
    unsigned char *seckey;
    unsigned char *newkey;
    int seckeylen, newkeylen, result;
    zval *privkey;
    zval *privkeylen;
    long compressed;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szzl",
            &seckey, &seckeylen,
            privkey,
            privkeylen,
            compressed
            ) == FAILURE) {
        return;
    }

    result = secp256k1_ec_privkey_export(seckey, newkey, &newkeylen, compressed);
    if (result) {
        newkey[newkeylen] = '\0';
        ZVAL_STRING(privkey, newkey, 1);
        ZVAL_LONG(privkeylen, newkeylen);
    }
    RETURN_LONG(result);
}






PHP_MINIT_FUNCTION(secp256k1) {

    REGISTER_LONG_CONSTANT("SECP256K1_START_VERIFY", SECP256K1_START_VERIFY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_START_SIGN", SECP256K1_START_SIGN, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

/* Remove if there's nothing to do at request start */
PHP_RINIT_FUNCTION(secp256k1) {
#if defined(COMPILE_DL_SECP256K1) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    return SUCCESS;
}

/* Remove if there's nothing to do at request end */
PHP_RSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(secp256k1) {
    php_info_print_table_start();
    php_info_print_table_header(2, "secp256k1 support", "enabled");
    php_info_print_table_end();
}

/* {{{ secp256k1_functions[]
 *
 * Every user visible function must have an entry in secp256k1_functions[].
 */
const zend_function_entry secp256k1_functions[] = {
    PHP_FE(secp256k1_start, NULL)
    PHP_FE(secp256k1_stop, NULL)
    PHP_FE(secp256k1_ec_seckey_verify, NULL)
    PHP_FE(secp256k1_ec_pubkey_verify, NULL)
    PHP_FE(secp256k1_ec_pubkey_create, NULL)
    PHP_FE(secp256k1_ec_pubkey_decompress, NULL)
    PHP_FE(secp256k1_ec_privkey_import, NULL)
    PHP_FE(secp256k1_ec_privkey_export, NULL)
    PHP_FE(secp256k1_ecdsa_verify, NULL)
    PHP_FE(secp256k1_ecdsa_sign, NULL)
    PHP_FE(secp256k1_test_by_reference, NULL)
    PHP_FE_END /* Must be the last line in secp256k1_functions[] */
};

zend_module_entry secp256k1_module_entry = {
    STANDARD_MODULE_HEADER,
    "secp256k1",
    secp256k1_functions,
    PHP_MINIT(secp256k1),
    PHP_MSHUTDOWN(secp256k1),
    PHP_RINIT(secp256k1), /* Replace with NULL if there's nothing to do at request start */
    PHP_RSHUTDOWN(secp256k1), /* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(secp256k1),
    PHP_SECP256K1_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SECP256K1
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(secp256k1)
#endif
