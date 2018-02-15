<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$msg32 = hash('sha256', 'this is a message!', true);
$privateKey = pack("H*", "88b59280e39997e49ebd47ecc9e3850faff5d7df1e2a22248c136cbdd0d60aae");
/** @var resource $signature */
$signature = '';

if (1 !== secp256k1_ecdsa_sign($context, $signature, $msg32, $privateKey)) {
    throw new \Exception("Failed to create signature");
}

$serialized = '';
secp256k1_ecdsa_signature_serialize_der($context, $serialized, $signature);
echo sprintf("Produced signature: %s \n", bin2hex($serialized));