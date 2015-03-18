<?php

namespace Afk11\Secp256k1Tests;

class Secp256k1Test extends TestCase {
    
    private $fixtures = [
        [
            "secKey" => "e7f8443bcb9dc0a65a056ff3b88342f37105d4f7eaf10fce8342297f7ecd96c5",
            "pubKey" => "03f29ced54e6343a35e047f5c1e01f01991ef7d6d6c16bd5ffe1b31b105975eb67",
            "pubKeyUncompressed" => "04f29ced54e6343a35e047f5c1e01f01991ef7d6d6c16bd5ffe1b31b105975eb67a59820317a4d88792609a7d5625304133762239f8459c8381c32b54aa646798d",
            "msg" => "fb3a3384783921e1bc394229481209f29f70c588f1c8092cb7e43fdcadcfe241",
            "sig" => "30450221008378d12c61651ae4a8ffd4dadfc3eebe9f1ff4013b43d527ddc39e7ca5ec50f3022070ff9eda96338d7df8e17f4a8913f790a586b1cd9a165f077b5c91fb19b35730",
        ],
    ];

    public function testVerifyPubKey() {
        foreach ($this->fixtures as $vector) {
            $this->assertEquals(1, secp256k1_ec_pubkey_verify(pack("H*", $vector['pubKey'])));
        }
    }

    public function testCreateSig() {
        foreach ($this->fixtures as $vector) {
            $sig = '';//str_pad("", 64, chr(1), STR_PAD_LEFT);
            $siglen = 0;
            $msg = $this->toBinary32($vector['msg']);
            $key = pack("H*", $vector['secKey']);
            $this->assertEquals(1, secp256k1_ecdsa_sign($msg, $sig, $siglen, $key));
        }
    }
    public function testVerifySecKey() {
        foreach ($this->fixtures as $vector) {
            $seckey = $this->toBinary32($vector['secKey']);
            $this->assertEquals(1, secp256k1_ec_seckey_verify($seckey));
        }
    }
    
    public function testCreatePubKey() {
        foreach ($this->fixtures as $vector) {
            $sec = $this->toBinary32($vector['secKey']);

            // compressed
            $pubKey = '';
            $pubKeyLen = 0;
            $this->assertEquals(1, secp256k1_ec_pubkey_create($pubKey, $pubKeyLen, $sec, 1));
            $this->assertEquals($vector['pubKey'], bin2hex($pubKey));
            
            // uncompressed
            // SET THIS TO NULL TO TRIGGER SEGFAULT?
            $pubKey = '';
            $pubKeyLen = 0;
            $this->assertEquals(1, secp256k1_ec_pubkey_create($pubKey, $pubKeyLen, $sec, 0));
            $this->assertEquals($vector['pubKeyUncompressed'], bin2hex($pubKey));
        }
    }
    
    public function testDecompressPubKey() {
        foreach ($this->fixtures as $vector) {
            $pubKey = pack("H*", $vector['pubKey']);
            $pubKeyLen = strlen($pubKey);
            $this->assertEquals(1, secp256k1_ec_pubkey_decompress($pubKey, $pubKeyLen));
            $this->assertEquals($vector['pubKeyUncompressed'], bin2hex($pubKey));
            $this->assertEquals(65, $pubKeyLen);
        }
    }

    public function testVerify() {
        foreach ($this->fixtures as $vector) {
            $this->assertEquals(1, secp256k1_ecdsa_verify($this->toBinary32($vector['msg']), pack("H*", $vector['sig']), pack("H*", $vector['pubKey'])));
        }
    }
}
