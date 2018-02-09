--TEST--
secp256k1_ec_privkey_tweak_add works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyTweaked = "";
$secKeyZero = str_repeat("\x00", 32);
$secKeyTwo = str_repeat("\x00", 31) . "\x02";
$secKeyOne = str_repeat("\x00", 31) . "\x01";
$secKeyOrderMinusOne = pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");

// (n-1) + 0 = (n-1)
$key = $secKeyOrderMinusOne;
$result = secp256k1_ec_privkey_tweak_add($context, $key, $secKeyZero);
echo $result . PHP_EOL;
echo unpack("H*", $key)[1] . PHP_EOL;

// (n-j) + j = n, bad
$key = $secKeyOrderMinusOne;
$result = secp256k1_ec_privkey_tweak_add($context, $key, $secKeyOne);
echo $result . PHP_EOL;
echo unpack("H*", $key)[1] . PHP_EOL;

$result = secp256k1_ec_seckey_verify($context, $key);
echo $result . PHP_EOL;

// (n-j) + j + 1 = n + 1 mod n = 1, fine!
$key = $secKeyOrderMinusOne;
$result = secp256k1_ec_privkey_tweak_add($context, $key, $secKeyTwo);
echo $result . PHP_EOL;
echo unpack("H*", $key)[1] . PHP_EOL;

$result = secp256k1_ec_seckey_verify($context, $key);
echo $result . PHP_EOL;

// 1 + 2 = 3
$result = secp256k1_ec_privkey_tweak_add($context, $key, $secKeyTwo);
echo $result . PHP_EOL;
echo unpack("H*", $key)[1] . PHP_EOL;

?>
--EXPECT--
1
fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
0
0000000000000000000000000000000000000000000000000000000000000000
0
1
0000000000000000000000000000000000000000000000000000000000000001
1
1
0000000000000000000000000000000000000000000000000000000000000003
