--TEST--
secp256k1_ecdsa_recover successfully extracts the public key
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$recid = 1;
$flags = SECP256K1_EC_UNCOMPRESSED;

$sig = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');
/** @var resource $s */
$s = null;
$result = secp256k1_ecdsa_recoverable_signature_parse_compact($context, $s, $sig, $recid);
echo $result . PHP_EOL;

$privateKey = pack("H*", 'fbb80e8a0f8af4fb52667e51963ac9860c192981f329debcc5d123a492a726af');

$publicKey = null;
$result = secp256k1_ec_pubkey_create($context, $publicKey, $privateKey);
echo $result . PHP_EOL;

$ePubKey = '';
$result = secp256k1_ec_pubkey_serialize($context, $ePubKey, $publicKey, $flags);
echo $result . PHP_EOL;
echo bin2hex($ePubKey) . PHP_EOL;

$msg = pack("H*", '03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13');

$recPubKey = null;
$result = secp256k1_ecdsa_recover($context, $recPubKey, $s, $msg);
echo $result . PHP_EOL;

$serPubKey = '';
$result = secp256k1_ec_pubkey_serialize($context, $serPubKey, $recPubKey, $flags);
echo $result . PHP_EOL;
echo bin2hex($serPubKey) . PHP_EOL;

?>
--EXPECT--
1
1
1
04985bfa6a0b27ba6e3b0b174d244043e9d9613ed09616e7eda720b24ac12d17e8c5bbf36d7fa4298f6e3e2da418cced16f1b3298e33f5fd22dbbb9d31f3d2fc93
1
1
04985bfa6a0b27ba6e3b0b174d244043e9d9613ed09616e7eda720b24ac12d17e8c5bbf36d7fa4298f6e3e2da418cced16f1b3298e33f5fd22dbbb9d31f3d2fc93
