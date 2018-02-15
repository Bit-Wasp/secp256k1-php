<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$publicKeyBin = pack("H*", "03fae8f5e64c9997749ef65c5db9f0ec3e121dc6901096c30da0f105a13212b6db");
$publicKey = null;
if (1 !== secp256k1_ec_pubkey_parse($context, $publicKey, $publicKeyBin)) {
    throw new \Exception("Invalid public key");
}

$tweak = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");
$result = secp256k1_ec_pubkey_tweak_add($context, $publicKey, $tweak);
if ($result == 1) {
    $pubKeyOut = '';
    secp256k1_ec_pubkey_serialize($context, $pubKeyOut, $publicKey, 1);
    echo sprintf("Tweaked public key: %s\n", unpack("H*", $pubKeyOut)[1]);
} else {
    throw new \Exception("Invalid public key or augend value");
}