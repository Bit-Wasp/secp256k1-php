--TEST--
secp256k1_schnorrsig_verify - bip vector 4 - returns true
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig64 = pack("H*", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4");
$msg32 = hex2bin("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703");
$pubKeyBin = pack("H*", "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9");
$sig = null;
$pubKey = null;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig64, $msg32, $pubKey);
echo $result.PHP_EOL;

?>
--EXPECT--
1
1