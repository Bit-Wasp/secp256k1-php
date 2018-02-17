--TEST--
ecdsa_signature_parse_der_lax works like secp256k1_ecdsa_signature_parse_der
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
declare(strict_types=1);
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
$sig = hex2bin("304402207a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed02204719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");

// Parse signature using lax DER encoding - not sure if fixture violates any rules
/** @var resource $laxSig */
$laxSig = null;
$result = ecdsa_signature_parse_der_lax($ctx, $laxSig, $sig);
echo $result . PHP_EOL;

?>
--EXPECT--
1
