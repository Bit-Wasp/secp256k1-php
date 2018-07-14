<?php
/**
 * auto generated file by PHPExtensionStubGenerator
 */

/**
 * Parse a signature in 'lax DER' format
 * 
 * Returns: 1 when the signature could be parsed, 0 otherwise.
 * 
 * @param resource $context
 * @param resource|null $ecdsaSignatureOut
 * @param string $sigLaxDerIn
 * @return int
 */
function ecdsa_signature_parse_der_lax($context, &$ecdsaSignatureOut, string $sigLaxDerIn): int {}
/**
 * Create a secp256k1 context object.
 * 
 * @param int $context
 * @return resource|null
 */
function secp256k1_context_create(int $context): ?resource {}
/**
 * Copies a secp256k1 context object.
 * 
 * @param resource $context
 * @return resource|null
 */
function secp256k1_context_clone($context): ?resource {}
/**
 * Destroy a secp256k1 context object.
 * 
 * The resource may not be used afterwards.
 * Args:   ctx: an existing context to destroy (cannot be NULL).
 * 
 * @param resource $context
 * @return bool
 */
function secp256k1_context_destroy($context): bool {}
/**
 * Parse a variable-length public key into the pubkey object.
 * 
 * Returns 1 if the public key was fully valid, 0 if the public key could not be parsed or is invalid.
 * 
 * @param resource $context
 * @param resource|null $ecPublicKey
 * @param string $publicKeyIn
 * @return int
 */
function secp256k1_ec_pubkey_parse($context, &$ecPublicKey, string $publicKeyIn): int {}
/**
 * Serialize a pubkey object into a serialized byte sequence.
 * 
 * Returns 1 always.
 * 
 * @param resource $context
 * @param string|null $publicKeyOut
 * @param resource $ecPublicKey
 * @param int $flags
 * @return int
 */
function secp256k1_ec_pubkey_serialize($context, ?string &$publicKeyOut, $ecPublicKey, int $flags): int {}
/**
 * Parse an ECDSA signature in compact (64 bytes) format.
 * 
 * Returns: 1 when the signature could be parsed, 0 otherwise.
 * 
 * @param resource $context
 * @param resource|null $ecdsaSignatureOut
 * @param string $sig64In
 * @return int
 */
function secp256k1_ecdsa_signature_parse_compact($context, &$ecdsaSignatureOut, string $sig64In): int {}
/**
 * Parse a DER ECDSA signature.
 * 
 * Returns: 1 when the signature could be parsed, 0 otherwise.
 * 
 * @param resource $context
 * @param resource|null $ecdsaSignatureOut
 * @param string $sigDerIn
 * @return int
 */
function secp256k1_ecdsa_signature_parse_der($context, &$ecdsaSignatureOut, string $sigDerIn): int {}
/**
 * Serialize an ECDSA signature in DER format.
 * 
 * Returns: 1 if enough space was available to serialize, 0 otherwise
 * 
 * @param resource $context
 * @param string|null $sigDerOut
 * @param resource $ecdsaSignature
 * @return int
 */
function secp256k1_ecdsa_signature_serialize_der($context, ?string &$sigDerOut, $ecdsaSignature): int {}
/**
 * Serialize an ECDSA signature in compact (64 byte) format.
 * 
 * Returns: 1
 * 
 * @param resource $context
 * @param string|null $sig64Out
 * @param resource $ecdsaSignature
 * @return int
 */
function secp256k1_ecdsa_signature_serialize_compact($context, ?string &$sig64Out, $ecdsaSignature): int {}
/**
 * Verify an ECDSA signature.
 * 
 * Returns: 1: correct signature.
 *          0: incorrect or unparseable signature.
 * 
 * @param resource $context
 * @param resource $ecdsaSignature
 * @param string $msg32
 * @param resource $ecPublicKey
 * @return int
 */
function secp256k1_ecdsa_verify($context, $ecdsaSignature, string $msg32, $ecPublicKey): int {}
/**
 * Convert a signature to a normalized lower-S form.
 * 
 * Returns: 1 if sigin was not normalized, 0 if it already was.
 * 
 * @param resource $context
 * @param resource|null $ecdsaSignatureNormalized
 * @param resource $ecdsaSignature
 * @return int
 */
function secp256k1_ecdsa_signature_normalize($context, &$ecdsaSignatureNormalized, $ecdsaSignature): int {}
/**
 * Create an ECDSA signature.
 * 
 * Returns: 1: signature created
 *          0: the nonce generation function failed, or the private key was invalid.
 * 
 * @param resource $context
 * @param resource|null $ecdsaSignatureOut
 * @param string $msg32
 * @param string $secretKey
 * @return int
 */
function secp256k1_ecdsa_sign($context, &$ecdsaSignatureOut, string $msg32, string $secretKey): int {}
/**
 * Verify an ECDSA secret key.
 * 
 * Returns: 1: secret key is valid
 *          0: secret key is invalid.
 * 
 * @param resource $context
 * @param string $secretKey
 * @return int
 */
function secp256k1_ec_seckey_verify($context, string $secretKey): int {}
/**
 * Compute the public key for a secret key.
 * 
 * Returns: 1: secret was valid, public key stores
 *          0: secret was invalid, try again.
 * 
 * @param resource $context
 * @param resource|null $ecPublicKey
 * @param string $secretKey
 * @return int
 */
function secp256k1_ec_pubkey_create($context, &$ecPublicKey, string $secretKey): int {}
/**
 * Negates a private key in place.
 * 
 * Returns: 1 always.
 * 
 * @param resource $context
 * @param string $secKey
 * @return int
 */
function secp256k1_ec_privkey_negate($context, string &$secKey): int {}
/**
 * Negates a public key in place.
 * 
 * Returns: 1 always.
 * 
 * @param resource $context
 * @param resource $ecPublicKey
 * @return int
 */
function secp256k1_ec_pubkey_negate($context, &$ecPublicKey): int {}
/**
 * Tweak a private key by adding tweak to it.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or if the resulting private key
 *          would be invalid (only when the tweak is the complement of the
 *          private key). 1 otherwise.
 * @param resource $context
 * @param string $seckey
 * @param string $tweak32
 * @return int
 */
function secp256k1_ec_privkey_tweak_add($context, string &$seckey, string $tweak32): int {}
/**
 * Tweak a public key by adding tweak times the generator to it.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or if the resulting public key
 *          would be invalid (only when the tweak is the complement of the
 *          corresponding private key). 1 otherwise.
 * 
 * @param resource $context
 * @param resource $ecPublicKey
 * @param string $tweak32
 * @return int
 */
function secp256k1_ec_pubkey_tweak_add($context, &$ecPublicKey, string $tweak32): int {}
/**
 * Tweak a private key by multiplying it by a tweak.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
 * 
 * @param resource $context
 * @param string $seckey
 * @param string $tweak32
 * @return int
 */
function secp256k1_ec_privkey_tweak_mul($context, string &$seckey, string $tweak32): int {}
/**
 * Tweak a public key by multiplying it by a tweak value.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
 * 
 * @param resource $context
 * @param resource $ecPublicKey
 * @param string $tweak32
 * @return int
 */
function secp256k1_ec_pubkey_tweak_mul($context, &$ecPublicKey, string $tweak32): int {}
/**
 * Updates the context randomization to protect against side-channel leakage.
 * 
 * Returns: 1: randomization successfully updated.
 *          0: error.
 * 
 * @param resource $context
 * @param string|null $seed32
 * @return int
 */
function secp256k1_context_randomize($context, ?string $seed32): int {}
/**
 * Add a number of public keys together.
 * 
 * Returns: 1: the sum of the public keys is valid.
 *          0: the sum of the public keys is not valid.
 * 
 * @param resource $context
 * @param resource|null $combinedEcPublicKey
 * @param array $publicKeys
 * @return int
 */
function secp256k1_ec_pubkey_combine($context, &$combinedEcPublicKey, array $publicKeys): int {}
/**
 * Parse a compact ECDSA signature (64 bytes + recovery id).
 * 
 * Returns: 1 when the signature could be parsed, 0 otherwise
 * 
 * @param resource $context
 * @param resource|null $ecdsaRecoverableSignatureOut
 * @param string $sig64
 * @param int $recId
 * @return int
 */
function secp256k1_ecdsa_recoverable_signature_parse_compact($context, &$ecdsaRecoverableSignatureOut, string $sig64, int $recId): int {}
/**
 * Convert a recoverable signature into a normal signature.
 * 
 * Returns: 1
 * 
 * @param resource $context
 * @param resource|null $ecdsaSignature
 * @param resource $ecdsaRecoverableSignature
 * @return int
 */
function secp256k1_ecdsa_recoverable_signature_convert($context, &$ecdsaSignature, $ecdsaRecoverableSignature): int {}
/**
 * Serialize an ECDSA signature in compact format (64 bytes + recovery id).
 * 
 * Returns: 1
 * 
 * @param resource $context
 * @param string|null $sig64Out
 * @param int|null $recIdOut
 * @param resource $ecdsaRecoverableSignature
 * @return int
 */
function secp256k1_ecdsa_recoverable_signature_serialize_compact($context, ?string &$sig64Out, ?int &$recIdOut, $ecdsaRecoverableSignature): int {}
/**
 * Create a recoverable ECDSA signature.
 * 
 * Returns: 1: signature created
 *          0: the nonce generation function failed, or the private key was invalid.
 * 
 * @param resource $context
 * @param resource|null $ecdsaRecoverableSignatureOut
 * @param string $msg32
 * @param string $secretKey
 * @return int
 */
function secp256k1_ecdsa_sign_recoverable($context, &$ecdsaRecoverableSignatureOut, string $msg32, string $secretKey): int {}
/**
 * Recover an ECDSA public key from a signature.
 * 
 * Returns: 1: public key successfully recovered (which guarantees a correct signature).
 *          0: otherwise.
 * 
 * @param resource $context
 * @param resource|null $ecPublicKey
 * @param resource $ecdsaRecoverableSignature
 * @param string $msg32
 * @return int
 */
function secp256k1_ecdsa_recover($context, &$ecPublicKey, $ecdsaRecoverableSignature, string $msg32): int {}
/**
 * Compute an EC Diffie-Hellman secret in constant time
 * 
 * Returns: 1: exponentiation was successful
 *          0: scalar was invalid (zero or overflow)
 * 
 * @param resource $context
 * @param string $result
 * @param resource $ecPublicKey
 * @param string $privKey
 * @return int
 */
function secp256k1_ecdh($context, string &$result, $ecPublicKey, string $privKey): int {}