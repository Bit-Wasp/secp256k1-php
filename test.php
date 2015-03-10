<?php


echo "Test secp256k1_ecdsa_verify: ";
$publicKey = pack("H*", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
$msg = pack("H*", "fb3a3384783921e1bc394229481209f29f70c588f1c8092cb7e43fdcadcfe241");
$sig = pack("H*", "3045022100987ceade6a304fc5823ab38f99fc3c5f772a2d3e89ea05931e2726105fc53b9e0220601fc3231f35962c714fcbce5c95b427496edc7ae8b3d12e93791d7629795b62");
var_dump(secp256k1_ecdsa_verify($msg, $sig, $publicKey));
echo "\n";

echo "Test secp256k1_ec_pubkey_verify: ";
$publicKey = pack("H*", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
var_dump(secp256k1_ec_pubkey_verify($publicKey));
echo "\n";

echo "Test secp256k1_ec_seckey_verify false: ";
var_dump(secp256k1_ec_seckey_verify(pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")));
echo "\n";

echo "Test secp256k1_ec_seckey_verify: ";
var_dump(secp256k1_ec_seckey_verify($msg));
echo "\n";


echo "Test secp256k1_test_by_reference: (10?) ";
$v = 'asdf';
secp256k1_test_by_reference($v);
var_dump($v);
echo "\n";

echo "Test secp256k1_ec_pubkey_create: ";
$seckey = 'ea0a18f3173de342029afd1d8ded525d51f72edcbb13250e627c316f8cf3f1b7';
$pubkey = 0;
$pubkeylen = 0;
var_dump(secp256k1_ec_pubkey_create($pubkey, $pubkeylen, $seckey, 0));
var_dump(bin2hex($pubkey), $pubkeylen);
echo "\n";

echo "Test secp256k1_ec_pubkey_decompress: ";
$pubkey2 = pack("H*", '0355764cb81dbb6760e82a39bbb9aef774964da3255724fbbe20a552f77938f539');
$pubkey = pack("H*", '0355764cb81dbb6760e82a39bbb9aef774964da3255724fbbe20a552f77938f539');
$pubkeylen = 33;
$expected = pack("H*", '0455764cb81dbb6760e82a39bbb9aef774964da3255724fbbe20a552f77938f53974f47be9246c0368cafe34d6b9b493f0a1e12ae61e46ab14e0223cac0c0ff417');
var_dump(secp256k1_ec_pubkey_decompress($pubkey, $pubkeylen));
echo "original: " . bin2hex($pubkey2) . "\n";
echo "now: " . bin2hex($pubkey) . "\n";
var_dump(bin2hex($pubkey), $pubkeylen);
var_dump($pubkey == $expected);
echo "\n";
