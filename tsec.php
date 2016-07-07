<?php
$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$privateKey = openssl_random_pseudo_bytes(32);
/** @var resource $publicKey */
$publicKey = '';

echo 'start'.PHP_EOL;
if (!secp256k1_ec_pubkey_create($context, $publicKey, $privateKey)) {
    die('oonoo');
}
var_dump($publicKey);
/*

$privateKey1 = openssl_random_pseudo_bytes(32);
$publicKey1 = '';
if (!secp256k1_ec_pubkey_create($context, $publicKey1, $privateKey1)) {
    die('oonoo');
}

secp256k1_ec_pubkey_tweak_mul($context, $publicKey1, $privateKey);

$serializedPub = '';
secp256k1_ec_pubkey_serialize($context, $serializedPub, $publicKey1, false);

echo "Priv1: " . bin2hex($privateKey1).PHP_EOL;
echo "Priv: " . bin2hex($privateKey).PHP_EOL;
echo "shared" . bin2hex($serializedPub).PHP_EOL;
*/