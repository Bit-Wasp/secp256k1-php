<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$compressed = true;
$publicKeyBin = pack("H*", "03fae8f5e64c9997749ef65c5db9f0ec3e121dc6901096c30da0f105a13212b6db");
$tweak = pack("H*", "0000000000000000000000000000000000000000000000000000000000000002");

/** @var resource $publicKey */
$publicKey = '';
if (1 !== secp256k1_ec_pubkey_parse($context, $publicKey, $publicKeyBin)) {
    throw new \Exception("Failed to parse public key");
}

$result = secp256k1_ec_pubkey_tweak_mul($context, $publicKey, $tweak);
if ($result == 1) {
    $serialized = '';
    secp256k1_ec_pubkey_serialize($context, $serialized, $publicKey, $compressed);
    echo sprintf("Tweaked public key: %s\n", unpack("H*", $serialized)[1]);
} else {
    throw new \Exception("Invalid public key or multiplicand value");
}