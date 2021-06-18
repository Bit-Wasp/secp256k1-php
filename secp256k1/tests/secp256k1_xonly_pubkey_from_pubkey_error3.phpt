--TEST--
secp256k1_xonly_pubkey_from_pubkey errors when pubkey is wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!constant_exists("SECP256K1_XONLY_PUBKEY_RES_NAME")) print "skip no extrakeys support";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$xonlyPubKey = null;
$parity = null;
$result = secp256k1_xonly_pubkey_from_pubkey($ctx, $xonlyPubKey, $parity, tmpfile());
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_xonly_pubkey_from_pubkey(): supplied resource is not a valid secp256k1_pubkey resource
0
