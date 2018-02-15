<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$publicKeyBin = pack("H*", '02ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414');

/** @var resource $publicKey */
$publicKey = '';
if (1 !== secp256k1_ec_pubkey_parse($context, $publicKey, $publicKeyBin)) {
    throw new \RuntimeException('Failed to parse public key');
}

$decompressed = '';
if (1 !== secp256k1_ec_pubkey_serialize($context, $decompressed, $publicKey, false /* whether to compress */)) {
    throw new \RuntimeException("Failed to serialize key");
}

echo unpack("H*", $decompressed)[1] . PHP_EOL;