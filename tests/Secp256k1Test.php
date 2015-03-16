<?php

class Secp256k1Test extends \PHPUnit_Framework_TestCase {
    
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
            $sig = '';
            $siglen = 0;
            $this->assertEquals(1, secp256k1_ecdsa_sign(pack("H*", $vector['msg']), $sig, $siglen, pack("H*", $vector['secKey'])));
        }
    }
    public function testVerifySecKey() {
        foreach ($this->fixtures as $vector) {
            $this->assertEquals(1, secp256k1_ec_seckey_verify(pack("H*", $vector['secKey'])));
        }
    }
    
    public function testCreatePubKey() {
        foreach ($this->fixtures as $vector) {
            // compressed
            $pubKey = null;
            $pubKeyLen = null;
            $this->assertEquals(1, secp256k1_ec_pubkey_create($pubKey, $pubKeyLen, pack("H*", $vector['secKey']), 1));
            // @TODO: can we move this to C?
            $pubKey = substr($pubKey, 0, $pubKeyLen);
            $this->assertEquals($vector['pubKey'], bin2hex($pubKey));
            
            // uncompressed
            $pubKey = null;
            $pubKeyLen = null;
            $this->assertEquals(1, secp256k1_ec_pubkey_create($pubKey, $pubKeyLen, pack("H*", $vector['secKey']), 0));
            // @TODO: can we move this to C?
            $pubKey = substr($pubKey, 0, $pubKeyLen);
            $this->assertEquals($vector['pubKeyUncompressed'], bin2hex($pubKey));
        }
    }
    
    public function testDecompressPubKey() {
        foreach ($this->fixtures as $vector) {
            $pubKey = pack("H*", $vector['pubKey']);
            $pubKeyLen = strlen($pubKey);
            
            $this->assertEquals(1, secp256k1_ec_pubkey_decompress($pubKey, $pubKeyLen));
            
            // @TODO: can we move this to C?
            $pubKey = substr($pubKey, 0, $pubKeyLen);
            $this->assertEquals($vector['pubKeyUncompressed'], bin2hex($pubKey));
        }
    }

    public function testVerify() {
        foreach ($this->fixtures as $vector) {
            $this->assertEquals(1, secp256k1_ecdsa_verify(pack("H*", $vector['msg']), pack("H*", $vector['sig']), pack("H*", $vector['pubKey'])));
        }
    }
}
