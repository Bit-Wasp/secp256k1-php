--TEST--
secp256k1_xonly_pubkey_tweak_verify throws if tweak is not 32 bytes
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$pubkey1 = null;
$tweakedPub = null;
$tweakEmpty = "";
$tweak31 = hex2bin("1c5bcae8f25cfff40a3cfb29bc59ed97d67e870f60c424aea12ea109696d37");
$tweak = hex2bin("1c5bcae8f25cfff40a3cfb29bc59ed97d67e870f60c424aea12ea109696d37ac");
$tweak33 = hex2bin("1c5bcae8f25cfff40a3cfb29bc59ed97d67e870f60c424aea12ea109696d37ac01");
$privKey1 = str_repeat("\x42", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619

$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;
echo get_resource_type($pubkey1) . PHP_EOL;

$hasSquareY = null;
$result = secp256k1_xonly_pubkey_tweak_add($ctx, $tweakedPub, $hasSquareY, $pubkey1, $tweak);
echo $result . PHP_EOL;
$expecting = "secp256k1_xonly_pubkey_tweak_verify(): Parameter 4 should be 32 bytes";

try {
    secp256k1_xonly_pubkey_tweak_verify($ctx, $tweakedPub, $hasSquareY, $pubkey1, $tweakEmpty);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}

try {
    secp256k1_xonly_pubkey_tweak_verify($ctx, $tweakedPub, $hasSquareY, $pubkey1, $tweak31);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}

try {
    secp256k1_xonly_pubkey_tweak_verify($ctx, $tweakedPub, $hasSquareY, $pubkey1, $tweak33);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}
?>
--EXPECT--
1
secp256k1_xonly_pubkey
1
secp256k1_xonly_pubkey_tweak_verify(): Parameter 4 should be 32 bytes
secp256k1_xonly_pubkey_tweak_verify(): Parameter 4 should be 32 bytes
secp256k1_xonly_pubkey_tweak_verify(): Parameter 4 should be 32 bytes