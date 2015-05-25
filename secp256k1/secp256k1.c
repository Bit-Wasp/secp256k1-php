/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_secp256k1.h"

#define MAX_SIGNATURE_LENGTH 72
#define COMPACT_SIGNATURE_LENGTH 64
#define PUBKEY_COMPRESSED_LENGTH 33
#define PUBKEY_UNCOMPRESSED_LENGTH 65
#define HASH_LENGTH 32
#define SECRETKEY_LENGTH 32
#define DERKEY_LENGTH 300

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_verify, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(0, signature)
    ZEND_ARG_INFO(0, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_sign, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(0, secretKey)
    ZEND_ARG_INFO(1, signature)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_sign_compact, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(0, secretKey)
    ZEND_ARG_INFO(1, signature)
    ZEND_ARG_INFO(1, recid)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_recover_compact, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(0, signature)
    ZEND_ARG_INFO(0, recid)
    ZEND_ARG_INFO(0, compressed)
    ZEND_ARG_INFO(1, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_seckey_verify, 0)
    ZEND_ARG_INFO(0, secretKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_verify, 0)
    ZEND_ARG_INFO(0, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_create, 0)
    ZEND_ARG_INFO(0, secretKey)
    ZEND_ARG_INFO(0, compressed)
    ZEND_ARG_INFO(1, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_decompress, 0)
    ZEND_ARG_INFO(1, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_import, 0)
    ZEND_ARG_INFO(0, privkey)
    ZEND_ARG_INFO(0, compressed)
    ZEND_ARG_INFO(1, seckey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_export, 0)
    ZEND_ARG_INFO(0, seckey)
    ZEND_ARG_INFO(0, compressed)
    ZEND_ARG_INFO(1, derkey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_tweak_add, 0)
    ZEND_ARG_INFO(1, seckey)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_tweak_add, 0)
    ZEND_ARG_INFO(1, publicKey)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_tweak_mul, 0)
    ZEND_ARG_INFO(1, seckey)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_tweak_mul, 0)
    ZEND_ARG_INFO(1, publicKey)
    ZEND_ARG_INFO(0, publicKeyLength)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_DECLARE_MODULE_GLOBALS(secp256k1)
static void php_secp256k1_init_globals(zend_secp256k1_globals *secp256k1_globals)
{
    secp256k1_globals->context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
}

int pubkeyLengthFromCompressed(int compressed)
{
    return compressed ? PUBKEY_COMPRESSED_LENGTH : PUBKEY_UNCOMPRESSED_LENGTH;
}

/**
 * Verify an ECDSA signature.
 *
 * In:
 *  msg32: the 32-byte message hash being verified (cannot be NULL)
 *  sig: the signature being verified (cannot be NULL)
 *  pubkey: the public key to verify with (cannot be NULL)

 * Returns:
 *  1: correct signature
 *  0: incorrect signature
 * -1: invalid public key
 * -2: invalid signature
 */
PHP_FUNCTION(secp256k1_ecdsa_verify) {
    secp256k1_context_t * context = SECP256K1_G(context);

    unsigned char *msg32, *sig, *pubkey;
    int msg32len, siglen, pubkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &msg32, &msg32len, &sig, &siglen, &pubkey, &pubkeylen) == FAILURE) {
        return;
    }

    int result = secp256k1_ecdsa_verify(context, msg32, sig, siglen, pubkey, pubkeylen);

    RETURN_LONG(result);
}

/**
 * Create an ECDSA signature.
 *
 * In:
 *  msg32:  the 32-byte message hash being signed (cannot be NULL)
 *  seckey: pointer to a 32-byte secret key (cannot be NULL)
 *
 * Out:
 *  sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *
 * Returns:
 *  1: signature created
 *  0: the nonce generation function failed, the private key was invalid, or there is not
 *     enough space in the signature.
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
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *signature;
    unsigned char *seckey, *msg32;
    int seckeylen, msg32len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssz", &msg32, &msg32len, &seckey, &seckeylen, &signature) == FAILURE) {
       return;
    }

    int newsiglen = MAX_SIGNATURE_LENGTH;
    unsigned char newsig[newsiglen];
    int result = secp256k1_ecdsa_sign(context, msg32, newsig, &newsiglen, seckey, NULL, NULL);
    if (result) {
        ZVAL_STRINGL(signature, newsig, newsiglen, 1);
    }

    RETURN_LONG(result);
}

/**
 * Create a compact ECDSA signature (64 byte + recovery id).
 *
 * In:
 *  msg32:  the 32-byte message hash being signed (cannot be NULL)
 *  seckey: pointer to a 32-byte secret key (cannot be NULL)
 *
 * Out:
 *  sig:    pointer to a 64-byte array where the signature will be placed (cannot be NULL)
 *          In case 0 is returned, the returned signature length will be zero.
 *  recid:  pointer to an int, which will be updated to contain the recovery id (can be NULL)
 *
 * Returns:
 *  1: signature created
 *  0: the nonce generation function failed, or the secret key was invalid.
 */
PHP_FUNCTION(secp256k1_ecdsa_sign_compact) {
    secp256k1_context_t * context = SECP256K1_G(context);

    unsigned char *seckey, *msg32;
    int seckeylen, msg32len;
    zval *signature, *recid;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sszz", &msg32, &msg32len, &seckey, &seckeylen, &signature, &recid) == FAILURE) {
       return;
    }

    unsigned char newsig[COMPACT_SIGNATURE_LENGTH];
    int newsiglen, newrecid;
    int result = secp256k1_ecdsa_sign_compact(context, msg32, newsig, seckey, NULL, NULL, &newrecid);
    if (result) {
        ZVAL_STRINGL(signature, newsig, 64, 1);
        ZVAL_LONG(recid, newrecid);
    }

    RETURN_LONG(result);
}

/**
 * Recover an ECDSA public key from a compact signature.
 *
 * In:
 *  msg32:      the 32-byte message hash assumed to be signed (cannot be NULL)
 *  sig64:      signature as 64 byte array (cannot be NULL)
 *  compressed: whether to recover a compressed or uncompressed pubkey
 *  recid:      the recovery id (0-3, as returned by ecdsa_sign_compact)
 *
 * Out:
 *  pubkey:     pointer to a 33 or 65 byte array to put the pubkey (cannot be NULL)
 *
 * => secp256k1_ecdsa_recover_compact($msg32, $signature, $recid, $compressed, $publicKey)
 *
 * Returns:
 *  1: public key successfully recovered (which guarantees a correct signature).
 *  0: otherwise.
 */
PHP_FUNCTION(secp256k1_ecdsa_recover_compact) {
    secp256k1_context_t * context = SECP256K1_G(context);

    unsigned char *msg32, *signature;
    long recid;
    int msg32len, signatureLen, compressed;
    zval *publicKey;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssllz", &msg32, &msg32len, &signature, &signatureLen, &recid, &compressed, &publicKey) == FAILURE) {
       return;
    }

    int newpubkeylen = pubkeyLengthFromCompressed(compressed);
    unsigned char newpubkey[newpubkeylen];
    int result = secp256k1_ecdsa_recover_compact(context, msg32, signature, newpubkey, &newpubkeylen, compressed, recid);
    if (result) {
        ZVAL_STRINGL(publicKey, newpubkey, newpubkeylen, 1);
    }

    RETURN_LONG(result);
}

/**
 * Verify an ECDSA secret key.

 * In:
 *  seckey: pointer to a 32-byte secret key (cannot be NULL)
 *
 * Returns:
 *  1: secret key is valid
 *  0: secret key is invalid
 */
PHP_FUNCTION(secp256k1_ec_seckey_verify) {
    secp256k1_context_t * context = SECP256K1_G(context);
    unsigned char *seckey;
    int seckeylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &seckey, &seckeylen) == FAILURE) {
        return;
    }

    int result = secp256k1_ec_seckey_verify(context, seckey);

    RETURN_LONG(result);
}

/**
 * Just validate a public key.
 *
 * In:
 *  pubkey:    pointer to a 33-byte or 65-byte public key (cannot be NULL).
 *  pubkeylen: length of pubkey
 *
 * Returns:
 *  1: valid public key
 *  0: invalid public key
 */
PHP_FUNCTION(secp256k1_ec_pubkey_verify) {
    secp256k1_context_t * context = SECP256K1_G(context);

    unsigned char *pubkey;
    int pubkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pubkey, &pubkeylen) == FAILURE) {
        return;
    }

    int result = secp256k1_ec_pubkey_verify(context, pubkey, pubkeylen);

    RETURN_LONG(result);
}

/**
 * Compute the public key for a secret key.
 *
 * In:
 *  compressed: whether the computed public key should be compressed
 *  seckey:     pointer to a 32-byte private key (cannot be NULL)
 *
 * Out:
 *  pubkey:     pointer to a 33-byte (if compressed) or 65-byte (if uncompressed)
 *              area to store the public key (cannot be NULL)
 *
 * Returns:
 *  1: secret was valid, public key stored
 *  0: secret was invalid, try again.
 */
PHP_FUNCTION(secp256k1_ec_pubkey_create) {
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *pubkey;
    unsigned char *seckey;
    int seckeylen, compressed;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &seckey, &seckeylen, &compressed, &pubkey) == FAILURE) {
        return;
    }

    int newpubkeylen = pubkeyLengthFromCompressed(compressed);
    unsigned char newpubkey[newpubkeylen];
    int result = secp256k1_ec_pubkey_create(context, newpubkey, &newpubkeylen, seckey, compressed);
    if (result) {
        ZVAL_STRINGL(pubkey, newpubkey, newpubkeylen, 1);
    }

    RETURN_LONG(result);
}

/**
 * Decompress a public key.
 *
 * In/Out:
 *  pubkey:    pointer to a 65-byte array to put the decompressed public key.
               It must contain a 33-byte or 65-byte public key already (cannot be NULL)
 *
 * Returns:
 *  0 if the passed public key was invalid, 1 otherwise.
 *  If 1 is returned, the pubkey is replaced with its decompressed version.
 */
PHP_FUNCTION(secp256k1_ec_pubkey_decompress) {
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *zPubKey;
    unsigned char *pubkey, newpubkey[PUBKEY_UNCOMPRESSED_LENGTH];
    int pubkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zPubKey) == FAILURE) {
        return;
    }

    if (Z_TYPE_P(zPubKey) != IS_STRING) {
        zend_error(E_WARNING, "secp256k1_ec_pubkey_decompress() expects parameter 1 to be string");
        return;
    }

    // Explicitly make a copy of this memory, as not to interfere with the original input variable.
    pubkey = Z_STRVAL_P(zPubKey);
    pubkeylen = Z_STRLEN_P(zPubKey);
    memcpy(newpubkey, pubkey, pubkeylen);
    int result = secp256k1_ec_pubkey_decompress(context, newpubkey, &pubkeylen);
    if (result) {
        ZVAL_STRINGL(zPubKey, newpubkey, pubkeylen, 1);
    }

    RETURN_LONG(result);
}

/**
 * Import a private key in DER format.
 */
PHP_FUNCTION (secp256k1_ec_privkey_import) {
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *zSecKey;
    unsigned char *derkey;
    int derkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &derkey, &derkeylen, &zSecKey) == FAILURE) {
        return;
    }

    unsigned char newseckey[SECRETKEY_LENGTH];
    int result = secp256k1_ec_privkey_import(context, newseckey, derkey, derkeylen);
    if (result) {
        ZVAL_STRINGL(zSecKey, newseckey, SECRETKEY_LENGTH, 1);
    }

    RETURN_LONG(result);
}

/**
 * Export a private key in DER format.
 */
PHP_FUNCTION (secp256k1_ec_privkey_export) {
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *zDerKey;
    unsigned char *seckey;
    int seckeylen, compressed;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &seckey, &seckeylen, &compressed, &zDerKey) == FAILURE) {
        return;
    }

    int newkeylen = DERKEY_LENGTH;
    unsigned char newkey[newkeylen];
    int result = secp256k1_ec_privkey_export(context, seckey, newkey, &newkeylen, compressed);
    if (result) {
        ZVAL_STRINGL(zDerKey, newkey, newkeylen, 1);
    }

    RETURN_LONG(result);
}

/**
 * Tweak a private key by adding tweak to it.
 */
PHP_FUNCTION (secp256k1_ec_privkey_tweak_add) {
    secp256k1_context_t * context = SECP256K1_G(context);
    zval *zSecKey;
    unsigned char *newseckey, *tweak;
    int tweaklen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zSecKey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    if (Z_TYPE_P(zSecKey) != IS_STRING) {
        zend_error(E_WARNING, "secp256k1_ec_privkey_tweak_add() expects parameter 1 to be string");
        return;
    }

    newseckey = Z_STRVAL_P(zSecKey);
    int result = secp256k1_ec_privkey_tweak_add(context, newseckey, tweak);
    if (result) {
        // Final arg is zero, don't destroy newseckey memory
        ZVAL_STRINGL(zSecKey, newseckey, SECRETKEY_LENGTH, 0);
    }

    RETURN_LONG(result);
}

/**
 * Tweak a public key by adding tweak times the generator to it
 */
PHP_FUNCTION (secp256k1_ec_pubkey_tweak_add) {
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *zPubKey;
    unsigned char *tweak, *newpubkey;
    int tweaklen, newpubkeylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zPubKey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    if (Z_TYPE_P(zPubKey) != IS_STRING) {
        zend_error(E_WARNING, "secp256k1_ec_zPubKey_tweak_add() expects parameter 1 to be string");
        return;
    }

    newpubkey = Z_STRVAL_P(zPubKey);
    newpubkeylen = Z_STRLEN_P(zPubKey);
    int result = secp256k1_ec_pubkey_tweak_add(context, newpubkey, newpubkeylen, tweak);
    if (result) {
        // Final arg is zero, don't destroy newpubkey memory
        ZVAL_STRINGL(zPubKey, newpubkey, newpubkeylen, 0);
    }

    RETURN_LONG(result);
}

/**
 * Tweak a private key by multiplying it with tweak.
 */
PHP_FUNCTION (secp256k1_ec_privkey_tweak_mul) {
    secp256k1_context_t * context = SECP256K1_G(context);
    zval *zSecKey;
    unsigned char *tweak;
    int tweaklen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zSecKey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    if (Z_TYPE_P(zSecKey) != IS_STRING) {
        zend_error(E_WARNING, "secp256k1_ec_privkey_tweak_mul() expects parameter 1 to be string");
        return;
    }

    unsigned char *newseckey = Z_STRVAL_P(zSecKey);
    int result = secp256k1_ec_privkey_tweak_mul(context, newseckey, tweak);
    if (result) {
        // Final arg is zero, don't destroy newseckey memory
        ZVAL_STRINGL(zSecKey, newseckey, SECRETKEY_LENGTH, 0);
    }

    RETURN_LONG(result);
}

/**
 * Tweak a public key by multiplying it with tweak
 */
PHP_FUNCTION (secp256k1_ec_pubkey_tweak_mul) {
    secp256k1_context_t * context = SECP256K1_G(context);

    zval *zPubKey;
    unsigned char *tweak, *newpubkey;
    int tweaklen, newpubkeylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zPubKey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    if (Z_TYPE_P(zPubKey) != IS_STRING) {
        zend_error(E_WARNING, "secp256k1_ec_zPubKey_tweak_mul() expects parameter 1 to be string");
        return;
    }

    newpubkey = Z_STRVAL_P(zPubKey);
    newpubkeylen = Z_STRLEN_P(zPubKey);
    int result = secp256k1_ec_pubkey_tweak_mul(context, newpubkey, newpubkeylen, tweak);
    if (result) {
        // Final arg is zero, don't destroy newpubkey memory
        ZVAL_STRINGL(zPubKey, newpubkey, newpubkeylen, 0);
    }

    RETURN_LONG(result);
}

PHP_MINIT_FUNCTION(secp256k1) {
    REGISTER_LONG_CONSTANT("SECP256K1_CONTEXT_VERIFY", SECP256K1_CONTEXT_VERIFY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_CONTEXT_SIGN", SECP256K1_CONTEXT_SIGN, CONST_CS | CONST_PERSISTENT);
    ZEND_INIT_MODULE_GLOBALS(secp256k1, php_secp256k1_init_globals, NULL);
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

/* Remove if there's nothing to do at request start */
PHP_RINIT_FUNCTION(secp256k1) {
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
    PHP_FE(secp256k1_ecdsa_sign, arginfo_secp256k1_ecdsa_sign)
    PHP_FE(secp256k1_ecdsa_verify, arginfo_secp256k1_ecdsa_verify)
    PHP_FE(secp256k1_ecdsa_sign_compact, arginfo_secp256k1_ecdsa_sign_compact)
    PHP_FE(secp256k1_ecdsa_recover_compact, arginfo_secp256k1_ecdsa_recover_compact)
    PHP_FE(secp256k1_ec_seckey_verify, arginfo_secp256k1_ec_seckey_verify)
    PHP_FE(secp256k1_ec_pubkey_verify, arginfo_secp256k1_ec_pubkey_verify)
    PHP_FE(secp256k1_ec_pubkey_create, arginfo_secp256k1_ec_pubkey_create)
    PHP_FE(secp256k1_ec_pubkey_decompress, arginfo_secp256k1_ec_pubkey_decompress)
    PHP_FE(secp256k1_ec_privkey_import, arginfo_secp256k1_ec_privkey_import)
    PHP_FE(secp256k1_ec_privkey_export, arginfo_secp256k1_ec_privkey_export)
    PHP_FE(secp256k1_ec_privkey_tweak_add, arginfo_secp256k1_ec_privkey_tweak_add)
    PHP_FE(secp256k1_ec_privkey_tweak_mul, arginfo_secp256k1_ec_privkey_tweak_mul)
    PHP_FE(secp256k1_ec_pubkey_tweak_add, arginfo_secp256k1_ec_pubkey_tweak_add)
    PHP_FE(secp256k1_ec_pubkey_tweak_mul, arginfo_secp256k1_ec_pubkey_tweak_mul)
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
ZEND_GET_MODULE(secp256k1)
#endif
