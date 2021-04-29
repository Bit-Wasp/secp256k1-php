--TEST--
secp256k1_schnorrsig_verify errors when msg32 is wrong size
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig64 = pack("H*", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
$msg32 = substr(hash('sha256', "a message", true), 0, 16); // half necessary size
$pubKeyBin = pack("H*", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
$pubKey = null;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

try {
    echo secp256k1_schnorrsig_verify($ctx, $sig64, $msg32, $pubKey);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
1
secp256k1_schnorrsig_verify(): Parameter 3 should be 32 bytes