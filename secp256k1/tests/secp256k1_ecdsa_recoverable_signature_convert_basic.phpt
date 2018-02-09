--TEST--
secp256k1_ecdsa_recoverable_signature_convert works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$privKey = hash('sha256', 'private key', true);
$msg32 = hash('sha256', 'msg', true);

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

// Create recoverable signature
/** @var resource $recoverableSignature */
$recoverableSignature = null;
$result = secp256k1_ecdsa_sign_recoverable($context, $recoverableSignature, $msg32, $privKey);
echo $result . PHP_EOL;
echo get_resource_type($recoverableSignature) . PHP_EOL;

// Convert secp256k1_ecdsa_recoverable_signature -> secp256k1_ecdsa_signature
/** @var resource $convertedSig */
$convertedSig = null;
$result = secp256k1_ecdsa_recoverable_signature_convert($context, $convertedSig, $recoverableSignature);
echo $result . PHP_EOL;

// Create public key from private to verify
/** @var resource $publicKey */
$publicKey = null;
$result = secp256k1_ec_pubkey_create($context, $publicKey, $privKey);
echo $result . PHP_EOL;

// Verify the converted signature, should work!
$result = secp256k1_ecdsa_verify($context, $convertedSig, $msg32, $publicKey);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_recoverable_signature
1
1
1
