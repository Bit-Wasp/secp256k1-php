--TEST--
secp256k1_schnorrsig_sign works with bip vector 1
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

//https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
$privKey = hex2bin("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
//DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659

$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $privKey);
echo $result.PHP_EOL;

$xonlyPubKey = null;
$parity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $xonlyPubKey, $parity, $keypair);
echo $result.PHP_EOL;

$xonlyOutput32 = null;
$result = secp256k1_xonly_pubkey_serialize($ctx, $xonlyOutput32, $xonlyPubKey);
echo $result.PHP_EOL;

echo strtoupper(unpack("H*", $xonlyOutput32)[1]) . PHP_EOL;

$auxRand = hex2bin("0000000000000000000000000000000000000000000000000000000000000001");
$sig64 = null;
$msg32 = hex2bin("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");

$result = secp256k1_schnorrsig_sign($ctx, $sig64, $msg32, $keypair, 'secp256k1_nonce_function_bip340', $auxRand);
echo $result . PHP_EOL;

echo strtoupper(unpack("H*", $sig64)[1]) . PHP_EOL;

?>
--EXPECT--
1
1
1
DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659
1
6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A