<?php

echo " - initialize context ...\n";
$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
echo " - clone ... \n";
$clone = secp256k1_context_clone($context);
echo " - destroy clone ... \n";
secp256k1_context_destroy($clone);
echo " - randomize original ... \n";
secp256k1_context_randomize($context);

echo "Test key creation/serialization\n";
$testpubkey = pack("H*", '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235');
$pk = '';
if (!secp256k1_ec_pubkey_parse($context, $testpubkey, $pk)) {
   die('failed to parse public key');
}

$s = '';
if (!secp256k1_ec_pubkey_serialize($context, $pk, 0, $s)) {
   die('failed to serialize same public key');
}

if (!$s == $testpubkey) {
    die('failed on s(p()) == k');
}

echo " - init keypair ... \n";
$privkey = str_pad('', 32, "A");
$pubkey = '';
if (secp256k1_ec_pubkey_create($context, $privkey, $pubkey) !== 1) {
  die('failed to create public key');
}

echo " - obtained privkey  : " . bin2hex($privkey) . "\n";
echo " - test pubkey serialize(parse(serialize())) == serialize()\n";
$su = ''; secp256k1_ec_pubkey_serialize($context, $pubkey, 0, $su);
$p = ''; secp256k1_ec_pubkey_parse($context, $su, $p);
$su2 = ''; secp256k1_ec_pubkey_serialize($context, $p, 0, $su2);
if ($su2 != $su) {
   die('pubkey serialization woes');
}
$sc = ''; secp256k1_ec_pubkey_serialize($context, $pubkey, 1, $sc);
echo " - obtained pubkey u : " . bin2hex($su) . "\n";
echo " - obtained pubkey c : " . bin2hex($sc) . "\n";
echo " - try sign ... \n";
$msg32 = str_pad('', 32, "B");
$sig = '';
if (secp256k1_ecdsa_sign($context, $msg32, $privkey, $sig) !== 1) {
  die('failed to sign');
}

$sigStr ='';
if (secp256k1_ecdsa_signature_serialize_der($context, $sig, $sigStr) !== 1) {
   die('Failed to serialize a DER signature');
}
$sigStr ='';
if (secp256k1_ecdsa_signature_serialize_der($context, $sig, $sigStr) !== 1) {
   die('Failed to serialize a DER signature');
}

echo " -- signed! " . bin2hex($sigStr) . "\n";
$verify = secp256k1_ecdsa_verify($context, $msg32, $sig, $pubkey);
if (!$verify) {
  die('sig verification FAILED');
} else {
  echo ' - successful sig verification';
}

echo " - test serialization functions\n";

$cs = ''; $recid = '';
$pc = '';
$cs2 = '';
secp256k1_ecdsa_signature_serialize_compact($context, $sig, $cs, $recid);
secp256k1_ecdsa_signature_parse_compact($context, $cs, $pc, $recid);
secp256k1_ecdsa_signature_serialize_compact($context, $pc, $cs2, $recid);
if ($cs !== $cs) {
    die('COMPACT: serialize(parse(serialize())) !== serialize()');
}
echo "  - Serialize Compact - " . bin2hex($cs) . "\n"; 

$ds = '';
$pd = '';
$ds2 = '';
secp256k1_ecdsa_signature_serialize_der($context, $sig, $ds);
secp256k1_ecdsa_signature_parse_der($context, $ds, $pd);
secp256k1_ecdsa_signature_serialize_der($context, $pd, $ds2);
if ($cs !== $cs) {
    die('DER: serialize(parse(serialize())) !== serialize()');
}
echo "  - Serialize DER - " . bin2hex($ds) . "\n"; 


$priv = (str_pad('', 62, "0") . '01');
$origBin = pack("H*", $priv);
$pub = '';
if (!secp256k1_ec_pubkey_create($context, $origBin, $pub)) {
   die('failed converting priv to pub');
}

$privBin = pack("H*", $priv);
$inc = str_pad('', 62, "0") . '02';
$incBin = pack("H*", $inc);
secp256k1_ec_privkey_tweak_add($context, $privBin, $incBin);
$resHex = bin2hex($privBin);
if (gmp_cmp(gmp_init($resHex, 16), 3) !== 0) {
   die('privkey addition failed');
}
echo " - Test addition - 1 + 2 == 3\n";

$privBin = pack("H*", $priv);
$mulBin = pack("H*", $inc);
secp256k1_ec_privkey_tweak_mul($context, $privBin, $mulBin);
$resHex = bin2hex($privBin);
if (gmp_cmp(gmp_init($resHex, 16), gmp_init(2, 10)) !== 0) {
   die('privkey multiplication failed');
}
echo " - Test multiplication - 1 * 2 == 2\n";

$pub = '';
$incBin = pack("H*", $inc);
secp256k1_ec_pubkey_create($context, $origBin, $pub); // 1
secp256k1_ec_pubkey_tweak_add($context, $pub, $incBin); // + 2

$ver = '';
$verKey = str_pad('', 62, '0') . '03';
$verBin = pack("H*", $verKey);
secp256k1_ec_pubkey_create($context, $verBin, $ver);
$verOutBin = '';
secp256k1_ec_pubkey_serialize($context, $ver, 0, $verOutBin);
$pubBin = '';
secp256k1_ec_pubkey_serialize($context, $pub, 0, $pubBin);
if ($verOutBin !== $pubBin) {
    die('fail pubkey tweak add');
}
echo " - Test pubkey addition - pubkey_tweak_add(1*G, 2) = 3 *G\n";
echo "\n\nEND\n";
