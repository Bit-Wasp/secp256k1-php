--TEST--
secp256k1_ecdsa_verify errors when signature is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

// fixture came from our signatures.yml
$msg32 = \pack("H*", "9a09c2b6f2c9b0343c945fbbfe08247a4cbe");
$priv = \pack("H*", "31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad");

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$sigIn = tmpfile();
$pubKey = null;
$result = secp256k1_ec_pubkey_create($ctx, $pubKey, $priv);
echo $result . PHP_EOL;

$result = secp256k1_ecdsa_verify($ctx, $sigIn, $msg32, $pubKey);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_verify(): supplied resource is not a valid secp256k1_ecdsa_signature resource
boolean
false
