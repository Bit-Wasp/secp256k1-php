--TEST--
secp256k1_ecdsa_sign_recoverable throws exception is privkey is wrong size
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$privKey = substr(hash('sha256', 'private key', true), 0, 16);
$msg32 = hash('sha256', 'msg', true);

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

// Create recoverable signature
/** @var resource $recoverableSignature */
$recoverableSignature = null;

try {
    secp256k1_ecdsa_sign_recoverable($context, $recoverableSignature, $msg32, $privKey);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
secp256k1_ecdsa_sign_recoverable(): Parameter 3 should be 32 bytes
