<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1EcdsaVerifyTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/signatures.yml');

        $fixtures = array();
        foreach ($data['signatures'] as $vector) {
            $fixtures[] = array($vector['privkey'], $vector['msg'], $vector['sig']);
        }
        return $fixtures;
    }

    /**
     * Testing return value 1
     * @dataProvider getVectors
     */
    public function testEcdsaVerify($hexPrivKey, $msg, $sig)
    {
        $this->genericTest(
            $hexPrivKey,
            $msg,
            $sig,
            1,
            1
        );
    }

    /**
     * Testing return value 0
     */
    public function testVerifyFindsInvalidSig()
    {
        $this->genericTest(
            '17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5',
            '6c9504d3cb2f8fa684139adaac5b02f0400be6d1fb293c80cb78598e2402a77f',
            '3046022100f4c79320af03ab386d45e2b906dbfd01252b4266db48caa60a528e0832839b21022100a66c26642e616c8d85def781c3cf7e2c65902f23de4e1928b67667fefa650ce601',
            1,
            0
        );

    }

    /**
     * Testing return value -1
     */
    public function testVerifyRejectsInvalidPubkey()
    {
        $pubkey = '';
        $sig = $this->toBinary32('3046022100f4c79330af03ab386d45e2b906dbfd01252b4266db48caa60a528e0832839b21022100a66c26642e616c8d85def781c3cf7e2c65902f23de4e1928b67667fefa650ce601');
        $msg = $this->toBinary32('6c9504d3cb2f8fa684139adaac5b02f0400be6d1fb293c80cb78598e2402a77f');
        $context = $this->context();
        $this->assertEquals(-1, \secp256k1_ecdsa_verify($context, $msg, $sig, $pubkey));
    }

    /**
     * Testing return value -2
     */
    public function testVerifyRejectsInvalidSignature()
    {
        $this->genericTest(
            '17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5',
            '6c9504d3cb2f8fa684139adaac5b02f0400be6d1fb293c80cb78598e2402a77f',
            '',
            1,
            -2
        );
    }

    public function getErroneousTypeVectors()
    {
        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $public = '';
        $context = $this->context();
        $compressed = 0;
        $this->assertEquals(1, \secp256k1_ec_pubkey_create($context, $private, $compressed, $public), 'public');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $sig = $this->pack('304502206af189487988df26eb4c2b2c7d74b78e19822bbb2fc27dada0800019abd20b46022100f0e6c4dabd4970afe125f707fbd6d62e79e950bdb2b4b9700214779ae475b05d01');

        $array = array();
        $class = new Secp256k1EcdsaVerifyTest;
        $resource = openssl_pkey_new();

        return array(
            array($array, $sig, $public),
            array($msg32, $array, $public),
            array($msg32, $sig, $array),
            array($resource, $sig, $public),
            array($msg32, $resource, $public),
            array($msg32, $sig, $resource),
            array($class, $sig, $public),
            array($msg32, $class, $public),
            array($msg32, $sig, $class)
        );
    }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($msg32, $sig, $public)
    {
        $context = $this->context();
        $r = \secp256k1_ecdsa_verify($context, $msg32, $sig, $public);
    }

    public function testVerifyWithInvalidInput()
    {
        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $sig = $this->pack('304502206af189487988df26eb4c2b2c7d74b78e19822bbb2fc27dada0800019abd20b46022100f0e6c4dabd4970afe125f707fbd6d62e79e950bdb2b4b9700214779ae475b05d01');

        $public = '';
        $context = $this->context();
        $compressed = 0;
        $this->assertEquals(1, \secp256k1_ec_pubkey_create($context, $private, $compressed, $public), 'public');
        $this->assertEquals(1, \secp256k1_ecdsa_verify($context, $msg32, $sig, $public), 'initial check');

        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, '', $sig, $public), 'msg32 as empty string');
        $this->assertEquals(-2, \secp256k1_ecdsa_verify($context, $msg32, '', $public), 'sig as empty string');
        $this->assertEquals(-1, \secp256k1_ecdsa_verify($context, $msg32, $sig, ''), 'pubkey as empty string');

        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, 1, $sig, $public), 'msg32 as 1');
        $this->assertEquals(-2, \secp256k1_ecdsa_verify($context, $msg32, 1, $public), 'sig as 1');
        $this->assertEquals(-1, \secp256k1_ecdsa_verify($context, $msg32, $sig, 1), 'public as 1');

        $resource = gmp_init(10, 10);
        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, $resource, $sig, $public), 'msg32 as resource');
        $this->assertEquals(-2, \secp256k1_ecdsa_verify($context, $msg32, $resource, $public), 'sig as resource');
        $this->assertEquals(-1, \secp256k1_ecdsa_verify($context, $msg32, $sig, $resource), 'pubkey as resource');

/*
        -
            privkey: 17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5
            msg: 0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef
            sig: 304502206af189487988df26eb4c2b2c7d74b78e19822bbb2fc27dada0800019abd20b46022100f0e6c4dabd4970afe125f707fbd6d62e79e950bdb2b4b9700214779ae475b05d01
            */
    }

    /**
     * @param $privkey
     * @param $msg
     * @param $sig
     * @param $ePubCreate
     * @param $eSigCreate
     */
    private function genericTest($privkey, $msg, $sig, $ePubCreate, $eSigCreate)
    {
        $seckey = $this->toBinary32($privkey);
        $msg = $this->toBinary32($msg);
        $sig = $this->toBinary32($sig);
        
        $pubkey = '';
        $context = $this->context();
        $compressed = 0;
        $this->assertEquals($ePubCreate, \secp256k1_ec_pubkey_create($context, $seckey, $compressed, $pubkey));
        $this->assertEquals($eSigCreate, \secp256k1_ecdsa_verify($context, $msg, $sig, $pubkey));
    }
}
