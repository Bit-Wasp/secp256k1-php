<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$publicKeyBin = pack("H*", '04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c');

/** @var resource $publicKey */
$publicKey = '';
if (1 !== secp256k1_ec_pubkey_parse($context, $publicKey, $publicKeyBin)) {
    throw new \RuntimeException('Failed to parse public key');
}

$compressed = '';
if (1 !== secp256k1_ec_pubkey_serialize($context, $compressed, $publicKey, true /* whether to compress */)) {
    throw new \RuntimeException("Failed to serialize key");
}

echo unpack("H*", $compressed)[1] . PHP_EOL;