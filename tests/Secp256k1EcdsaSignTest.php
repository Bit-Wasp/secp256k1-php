<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1EcdsaSignTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/deterministicSignatures.yml');

        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array($vector['privkey'], $vector['msg'], substr($vector['sig'], 0, strlen($vector['sig'])-2));
        }
        return $fixtures;
    }

    /**
     * Testing return value 1
     * @dataProvider getVectors
     */
    public function testEcdsaSign($hexPrivKey, $msg, $sig)
    {
        $this->genericTest(
            $hexPrivKey,
            $msg,
            $sig,
            1
        );
    }

    /**
     * @param $privkeyhex
     * @param $msg
     * @param $expectedSig
     * @param $eSigCreate
     */
    private function genericTest($privkeyhex, $msg, $expectedSig, $eSigCreate)
    {
        $privkey = $this->toBinary32($privkeyhex);
        $msg = $this->toBinary32($msg);
        $ctx = $this->context();

        $signature = '';
        $sign = secp256k1_ecdsa_sign($ctx, $msg, $privkey, $signature);
        $this->assertEquals($eSigCreate, $sign);
        $this->assertEquals($expectedSig, bin2hex($signature));
        
        return;

        if ($eSigCreate == 1) {
            $pubkey = '';

            $this->assertEquals(1, secp256k1_ec_pubkey_create($ctx, $privkey, 0, $pubkey));
            $this->assertEquals(1, secp256k1_ecdsa_verify($ctx, $msg, $signature, $pubkey));
        }
    }


    public function getErroneousTypeVectors()
    {
        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');

        $array = array();
        $class = new Secp256k1EcdsaSignTest;
        $resource = openssl_pkey_new();

        return [
            [$array, $private],
            [$msg32, $array],
            [$resource, $private],
            [$msg32, $resource],
            [$class, $private],
            [$msg32, $class]
        ];
    }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($msg32, $private)
    {
        $sig = '';
        $ctx = $this->context();

        $r = \secp256k1_ecdsa_sign($ctx, $msg32, $private, $sig);
    }

    public function testforProblemsWithReference()
    {

        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $a = array();
        $ctx = $this->context();
        $this->assertEquals(1, \secp256k1_ecdsa_sign($ctx, $msg32, $private, $a));
    }
}
