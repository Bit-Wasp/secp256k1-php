<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secretKey = pack("H*", "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd");
if (secp256k1_ec_seckey_verify($context, $secretKey) !== 1) {
    throw new \Exception("Private key was invalid");
}

echo "Private key was valid\n";