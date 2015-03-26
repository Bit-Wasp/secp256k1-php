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
        $this->assertEquals(-1, secp256k1_ecdsa_verify($msg, $sig, $pubkey));
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
        $this->assertEquals($ePubCreate, secp256k1_ec_pubkey_create($seckey, 0, $pubkey));
        $this->assertEquals($eSigCreate, secp256k1_ecdsa_verify($msg, $sig, $pubkey));
    }
}
