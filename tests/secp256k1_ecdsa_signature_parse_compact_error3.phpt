--TEST--
secp256k1_ecdsa_signature_parse_compact returns false if garbage signature given
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$sigIn = str_repeat("\xff", 64);
$sig = null;
$result = secp256k1_ecdsa_signature_parse_compact($ctx , $sig, $sigIn);
echo $result . PHP_EOL;

?>
--EXPECT--
0