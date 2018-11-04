--TEST--
secp256k1_ecdsa_sign_recoverable fails with 0 private key
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

// fixture came from our signatures.yml
$msg32 = \pack("H*", "9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe");
$priv = \str_repeat("\x00", 32);

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig = null;
$result = secp256k1_ecdsa_sign_recoverable($ctx, $sig, $msg32, $priv);
echo $result . PHP_EOL;

?>
--EXPECT--
0