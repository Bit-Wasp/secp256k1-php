--TEST--
ecdsa_signature_parse_der_lax and secp256k1_ecdsa_signature_serialize_der cooperate
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
$sig = hex2bin("304402207a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed02204719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");

// Parse signature using lax DER encoding
/** @var resource $laxSig */
$laxSig = null;
$result = ecdsa_signature_parse_der_lax($ctx, $laxSig, $sig);
echo $result . PHP_EOL;
echo get_resource_type($laxSig) . PHP_EOL;

// Parse signature using lax DER encoding
$sigOut = '';
$result = secp256k1_ecdsa_signature_serialize_der($ctx, $sigOut, $laxSig);
echo $result . PHP_EOL;
echo unpack("H*", $sigOut)[1] . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_signature
1
304402207a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed02204719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7