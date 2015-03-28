<?php

namespace BitWasp\Secp256k1Tests;


class Secp256k1EcdsaSignCompact extends TestCase
{
    public function testSignCompact()
    {
        $key = $this->toBinary32('404630ea0d36ec5fe8b036139872789bee54246233d9529661ccaf976f02904a');
        $msg = $this->toBinary32('03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13');

        $sig = '';
        $recid = 0;

        $this->assertEquals(1, secp256k1_ecdsa_sign_compact($msg, $key, $sig, $recid));

        $this->assertEquals('ebbf6d178d0d44ae8c2e42a52153199bfe9f33aa89eed264493e9ef965ee519840b4fe3bd58fa89eb65352eb969aaa7e309bd9d0eae6fe10695f4e7d10f1fd8e', bin2hex($sig));
        $this->assertEquals(1, $recid);
    }

    public function testRandomSign()
    {
        for($i = 0; $i < 5; $i++) {
            $compressed = ($i%2==0);
            $private = $this->getPrivate();
            $publicKey = '';
            $this->assertEquals(1, secp256k1_ec_pubkey_create($private, $compressed, $publicKey));

            $msg = hash('sha256', $i, true);
            $sig = '';
            $recid = 0;
            $this->assertEquals(1, secp256k1_ecdsa_sign_compact($msg, $private, $sig, $recid));

            $byte = 27 + $recid + ($compressed ? 4 : 0);
            $byteHex = str_pad(dechex($byte), 2, '0', STR_PAD_LEFT);
            $bin = hex2bin($byteHex) . $sig;
            $base64 = base64_encode($bin);

            $this->decodeTest($base64, $msg, $recid, $compressed, $publicKey);

        }
    }

    public function decodeTest($base64, $hash, $expectedRecid, $expectedCompressed, $expectedPubkeyBS)
    {
        $bin = base64_decode($base64);
        $recoveryFlags = ord($bin[0]) - 27;
        $compressed = ($recoveryFlags & 4) != 0;
        $recid = $recoveryFlags - ($compressed ? 4 : 0);

        $sig = substr($bin, 1);

        $publicKey = '';
        $this->assertEquals(1, secp256k1_ecdsa_recover_compact($hash, $sig, $recid, $compressed, $publicKey));
        $this->assertEquals($expectedPubkeyBS, $publicKey);
        $this->assertEquals($expectedRecid, $recid);
        $this->assertEquals($expectedCompressed, $compressed);
    }
}