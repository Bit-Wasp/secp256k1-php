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


echo "Test secp256k1_ec_pubkey_create: ";
$seckey = pack("H*", 'ea0a18f3173de342029afd1d8ded525d51f72edcbb13250e627c316f8cf3f1b7');
$pubkey = '';
$pubkeylen = 0;
var_dump(secp256k1_ec_pubkey_create($pubkey, $pubkeylen, $seckey, 0));
var_dump(bin2hex($pubkey), $pubkeylen);
echo "\n";




echo "Test secp256k1_ec_pubkey_tweak_mul: \n";
$seckey = pack("H*", '17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
$tweak  = pack("H*", '0101010101010101010101010101010101010101010101010101010101010101');
$pub = '';
$publen = 0;
$r = secp256k1_ec_pubkey_create($pub, $publen, $seckey, 0);
var_dump(secp256k1_ec_pubkey_tweak_mul($pub, $publen, $tweak));
var_dump(bin2hex($pubkey));
echo "\n";

echo "Test secp256k1_ec_privkey_tweak_Add: \n";
$seckey = pack("H*", '17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
$tweak  = pack("H*", '0101010101010101010101010101010101010101010101010101010101010101');
var_dump(secp256k1_ec_privkey_tweak_add($seckey, $tweak));
var_dump(bin2hex($seckey));
echo "\n";

echo "Test secp256k1_ec_pubkey_decompress: ";
$pubkey = pack("H*", '0355764cb81dbb6760e82a39bbb9aef774964da3255724fbbe20a552f77938f539');
$pubkeylen = 33;
$expected = pack("H*", '0455764cb81dbb6760e82a39bbb9aef774964da3255724fbbe20a552f77938f53974f47be9246c0368cafe34d6b9b493f0a1e12ae61e46ab14e0223cac0c0ff417');
var_dump(secp256k1_ec_pubkey_decompress($pubkey, $pubkeylen));
echo "now: " . bin2hex($pubkey) . "\n";
var_dump(bin2hex($pubkey), $pubkeylen);
echo "\n";


echo "Test secp256k1_ecdsa_sign: ";
echo "segfault ? \n";
$seckey = pack("H*", "ea0a18f3173de342029afd1d8ded525d51f72edcbb13250e627c316f8cf3f1b7");
echo "(a)\n";
$msg = pack("H*", "fb3a3384783921e1bc394229481209f29f70c588f1c8092cb7e43fdcadcfe241");
echo "(b)\n";
$signature = '';
echo "(c)\n";
$siglen = 0;
echo "(start_sign)\n";
$sign = secp256k1_ecdsa_sign($msg, $signature, $siglen, $seckey);
var_dump(bin2hex($signature), $siglen);
echo $signature."\n";


echo "Test secp256k1_ec_privkey_export: ";
$seckey = pack("H*", 'ea0a18f3173de342029afd1d8ded525d51f72edcbb13250e627c316f8cf3f1b7');
$der = 'a';
$derlen = strlen($der);
$compressed = 1;
var_dump(secp256k1_ec_privkey_export($seckey, $der, $derlen, $compressed));
var_dump(bin2hex($der), $derlen);
echo "(e)\n";


