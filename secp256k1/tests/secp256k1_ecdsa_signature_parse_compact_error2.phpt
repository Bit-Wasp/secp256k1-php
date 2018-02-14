--TEST--
secp256k1_ecdsa_signature_parse_compact returns false if invalid resource type given
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$badCtx = tmpfile();

$sigIn = hex2bin("7a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed4719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");
$sig = null;
$result = secp256k1_ecdsa_signature_parse_compact($badCtx, $sig, $sigIn);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;


?>
--EXPECT--
secp256k1_ecdsa_signature_parse_compact(): supplied resource is not a valid secp256k1_context resource
boolean
false
