--TEST--
secp256k1_ecdsa_sign_recoverable and secp256k1_ecdsa_recover are consistent
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

// Recover public key from the signature
/** @var resource $recoveredPublicKey */
$recoveredPublicKey = null;
$result = secp256k1_ecdsa_recover($context, $recoveredPublicKey, $recoverableSignature, $msg32);
echo $result . PHP_EOL;

// Create public key from private to double check
/** @var resource $expectedPublicKey */
$expectedPublicKey = null;
$result = secp256k1_ec_pubkey_create($context, $expectedPublicKey, $privKey);
echo $result . PHP_EOL;

// Compare the two public keys
$sPubkey = null;
$result = secp256k1_ec_pubkey_serialize($context, $sPubkey, $expectedPublicKey, 1);
echo $result . PHP_EOL;

$srPubkey = null;
$result = secp256k1_ec_pubkey_serialize($context, $srPubkey, $recoveredPublicKey, 1);
echo $result . PHP_EOL;

echo unpack("H*", $sPubkey)[1] . PHP_EOL;
echo unpack("H*", $srPubkey)[1] . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_recoverable_signature
1
1
1
1
02bb0cc84db7b318cb9f3521b809530440de0870f8e53d075298d06b10018162b8
02bb0cc84db7b318cb9f3521b809530440de0870f8e53d075298d06b10018162b8