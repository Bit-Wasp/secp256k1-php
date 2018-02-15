<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$privateKey = pack("H*", "88b59280e39997e49ebd47ecc9e3850faff5d7df1e2a22248c136cbdd0d60aae");
$tweak = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");

$result = secp256k1_ec_privkey_tweak_add($context, $privateKey, $tweak);
if ($result == 1) {
    echo sprintf("Tweaked private key: %s\n", bin2hex($privateKey));
} else {
    throw new \Exception("Invalid private key or augend value");
}