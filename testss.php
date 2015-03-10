<?php
var_dump(secp256k1_start(0));

$privateKey = pack("H*", "");
$publicKey = pack("H*", "");
$msg32 = pack("H*", "");
$sig = pack("H*", "");

list ($privateKeyLen, $publicKeyLen, $sigLen) = 
  array(
    strlen($privateKey),
    strlen($publicKey),
    strlen($sig)
  );

secp256k1_ecdsa_verify($msg32, $sig, $publicKey);
