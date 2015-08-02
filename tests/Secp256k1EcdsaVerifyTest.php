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
        $context = TestCase::getContext();
        foreach ($data['signatures'] as $vector) {
            $fixtures[] = array($context, $vector['privkey'], $vector['msg'], $vector['sig']);
        }
        return $fixtures;
    }

    /**
     * Testing return value 1
     * @dataProvider getVectors
     */
    public function testEcdsaVerify($context, $hexPrivKey, $msg, $sig)
    {
        $this->genericTest(
            $context,
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
            TestCase::getContext(),
            '17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5',
            '6c9504d3cb2f8fa684139adaac5b02f0400be6d1fb293c80cb78598e2402a77f',
            '3046022100f4c79320af03ab386d45e2b906dbfd01252b4266db48caa60a528e0832839b21022100a66c26642e616c8d85def781c3cf7e2c65902f23de4e1928b67667fefa650ce601',
            1,
            0
        );

    }

    public function getErroneousTypeVectors()
    {
        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $public = '';
        $context = TestCase::getContext();
        $this->assertEquals(1, \secp256k1_ec_pubkey_create($context, $private, $public), 'public');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $sig = $this->pack('304502206af189487988df26eb4c2b2c7d74b78e19822bbb2fc27dada0800019abd20b46022100f0e6c4dabd4970afe125f707fbd6d62e79e950bdb2b4b9700214779ae475b05d01');

        $array = array();
        $class = new Secp256k1EcdsaVerifyTest;
        $resource = openssl_pkey_new();

        return array(
            array($context, $array, $sig, $public),
            array($context, $msg32, $array, $public),
            array($context, $msg32, $sig, $array),
            array($context, $resource, $sig, $public),
            array($context, $msg32, $resource, $public),
            array($context, $msg32, $sig, $resource),
            array($context, $class, $sig, $public),
            array($context, $msg32, $class, $public),
            array($context, $msg32, $sig, $class)
        );
    }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException \PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($context, $msg32, $sig, $public)
    {
        $s = '';
        $p = '';
        secp256k1_ecdsa_signature_parse_der($context, $sig, $s);
        secp256k1_ec_pubkey_parse($context, $public, $p);

        \secp256k1_ecdsa_verify($context, $msg32, $s, $p);
    }

    public function testVerifyWithInvalidInput()
    {
        $context = TestCase::getContext();
        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $sig = $this->pack('304502206af189487988df26eb4c2b2c7d74b78e19822bbb2fc27dada0800019abd20b46022100f0e6c4dabd4970afe125f707fbd6d62e79e950bdb2b4b9700214779ae475b05d01');

        $s = '';
        secp256k1_ecdsa_signature_parse_der($context, $sig, $s);
        $public = '';
        $this->assertEquals(1, \secp256k1_ec_pubkey_create($context, $private, $public), 'public');
        $this->assertEquals(1, \secp256k1_ecdsa_verify($context, $msg32, $s, $public), 'initial check');

        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, '', $s, $public), 'msg32 as empty string');

        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, 1, $s, $public), 'msg32 as 1');
        

    }

    /**
     * @param $privkey
     * @param $msg
     * @param $sig
     * @param $ePubCreate
     * @param $eSigCreate
     */
    private function genericTest($context, $privkey, $msg, $sig, $ePubCreate, $eSigCreate)
    {
        $seckey = $this->toBinary32($privkey);
        $msg = $this->toBinary32($msg);
        $sig = $this->toBinary32($sig);
        
        $pubkey = '';
        $this->assertEquals($ePubCreate, \secp256k1_ec_pubkey_create($context, $seckey, $pubkey));

        $s = '';
        secp256k1_ecdsa_signature_parse_der($context, $sig, $s);
        $this->assertEquals($eSigCreate, \secp256k1_ecdsa_verify($context, $msg, $s, $pubkey));
    }
}
