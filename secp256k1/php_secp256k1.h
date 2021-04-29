/* $Id$ */
#include <secp256k1.h>
#ifdef SECP256K1_MODULE_ECDH
#include <secp256k1_ecdh.h>
#endif
#ifdef SECP256K1_MODULE_RECOVERY
#include <secp256k1_recovery.h>
#endif
#ifdef SECP256K1_MODULE_SCHNORRSIG
#include <secp256k1_schnorrsig.h>
#endif

#ifndef PHP_SECP256K1_H
#define PHP_SECP256K1_H

extern zend_module_entry secp256k1_module_entry;
#define phpext_secp256k1_ptr &secp256k1_module_entry

#define PHP_SECP256K1_VERSION "0.2.0"
#define SECP256K1_CTX_RES_NAME "secp256k1_context"
#define SECP256K1_PUBKEY_RES_NAME "secp256k1_pubkey"
#define SECP256K1_SIG_RES_NAME "secp256k1_ecdsa_signature"
#define SECP256K1_SCRATCH_SPACE_RES_NAME "secp256k1_scratch_space"
#ifdef SECP256K1_MODULE_RECOVERY
#define SECP256K1_RECOVERABLE_SIG_RES_NAME "secp256k1_ecdsa_recoverable_signature"
#endif

#ifdef SECP256K1_MODULE_EXTRAKEYS
#define SECP256K1_XONLY_PUBKEY_RES_NAME "secp256k1_xonly_pubkey"
#define SECP256K1_KEYPAIR_RES_NAME "secp256k1_keypair"
#endif

#ifdef SECP256K1_MODULE_SCHNORRSIG
#endif

#ifdef ZTS
# define SECP256K1_G(v) TSRMG(secp256k1_globals_id, zend_secp256k1_globals *, v)
#else
# define SECP256K1_G(v) (secp256k1_globals.v)
#endif

#define MAX_SIGNATURE_LENGTH 72
#define SCHNORRSIG_LENGTH 64
#define COMPACT_SIGNATURE_LENGTH 64
#define PUBKEY_COMPRESSED_LENGTH 33
#define PUBKEY_UNCOMPRESSED_LENGTH 65
#define HASH_LENGTH 32
#define SECRETKEY_LENGTH 32
#define DERKEY_LENGTH 300

PHP_FUNCTION(secp256k1_context_create);
PHP_FUNCTION(secp256k1_context_destroy);
PHP_FUNCTION(secp256k1_context_clone);
PHP_FUNCTION(secp256k1_context_randomize);

PHP_FUNCTION(secp256k1_ecdsa_verify);
PHP_FUNCTION(secp256k1_ecdsa_sign);
PHP_FUNCTION(secp256k1_ecdsa_signature_parse_der);
PHP_FUNCTION(secp256k1_ecdsa_signature_parse_compact);
PHP_FUNCTION(ecdsa_signature_parse_der_lax);
PHP_FUNCTION(secp256k1_ecdsa_signature_serialize_der);
PHP_FUNCTION(secp256k1_ecdsa_signature_serialize_compact);
PHP_FUNCTION(secp256k1_ecdsa_signature_normalize);

PHP_FUNCTION(secp256k1_ec_seckey_verify);
PHP_FUNCTION(secp256k1_ec_privkey_negate);
PHP_FUNCTION(secp256k1_ec_pubkey_negate);
PHP_FUNCTION(secp256k1_ec_pubkey_create);
PHP_FUNCTION(secp256k1_ec_pubkey_parse);
PHP_FUNCTION(secp256k1_ec_pubkey_serialize);

PHP_FUNCTION(secp256k1_ec_privkey_tweak_add);
PHP_FUNCTION(secp256k1_ec_privkey_tweak_mul);
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_add);
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_mul);

PHP_FUNCTION(secp256k1_ec_pubkey_combine);

PHP_FUNCTION(secp256k1_scratch_space_create);
PHP_FUNCTION(secp256k1_scratch_space_destroy);

PHP_FUNCTION(secp256k1_nonce_function_default);
PHP_FUNCTION(secp256k1_nonce_function_rfc6979);

/* Recovery module */
#ifdef SECP256K1_MODULE_RECOVERY
PHP_FUNCTION(secp256k1_ecdsa_sign_recoverable);
PHP_FUNCTION(secp256k1_ecdsa_recover);
PHP_FUNCTION(secp256k1_ecdsa_recoverable_signature_convert);
PHP_FUNCTION(secp256k1_ecdsa_recoverable_signature_serialize_compact);
PHP_FUNCTION(secp256k1_ecdsa_recoverable_signature_parse_compact);
#endif /* end of ecdh module */

/* ECDH module */
#ifdef SECP256K1_MODULE_ECDH
PHP_FUNCTION(secp256k1_ecdh);
#endif /* end of ecdh module */


/* extrakeys module */
#ifdef SECP256K1_MODULE_EXTRAKEYS
PHP_FUNCTION(secp256k1_xonly_pubkey_parse);
PHP_FUNCTION(secp256k1_xonly_pubkey_serialize);
PHP_FUNCTION(secp256k1_xonly_pubkey_from_pubkey);
PHP_FUNCTION(secp256k1_xonly_pubkey_tweak_add);
PHP_FUNCTION(secp256k1_xonly_pubkey_tweak_add_check);
PHP_FUNCTION(secp256k1_keypair_create);
PHP_FUNCTION(secp256k1_keypair_sec);
PHP_FUNCTION(secp256k1_keypair_pub);
PHP_FUNCTION(secp256k1_keypair_xonly_pub);
PHP_FUNCTION(secp256k1_keypair_xonly_tweak_add);
#endif /* end of schnorrsig module */

/* schnorr module */
#ifdef SECP256K1_MODULE_SCHNORRSIG
PHP_FUNCTION(secp256k1_schnorrsig_sign);
PHP_FUNCTION(secp256k1_schnorrsig_verify);
PHP_FUNCTION(secp256k1_nonce_function_bip340);
#endif /* end of schnorrsig module */

#endif	/* PHP_SECP256K1_H */
