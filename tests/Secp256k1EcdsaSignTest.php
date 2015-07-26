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
        $context = TestCase::getContext();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array($context, $vector['privkey'], $vector['msg'], substr($vector['sig'], 0, strlen($vector['sig'])-2));
        }
        return $fixtures;
    }

    /**
     * Testing return value 1
     * @dataProvider getVectors
     */
    public function testEcdsaSign($context, $hexPrivKey, $msg, $sig)
    {
        $this->genericTest(
            $context,
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
    private function genericTest($context, $privkeyhex, $msg, $expectedSig, $eSigCreate)
    {
        $privkey = $this->toBinary32($privkeyhex);
        $msg = $this->toBinary32($msg);

        $signature = '';
        $sign = secp256k1_ecdsa_sign($context, $msg, $privkey, $signature);
        $this->assertEquals($eSigCreate, $sign);
        $this->assertEquals($expectedSig, bin2hex($signature));
        
        return;

        if ($eSigCreate == 1) {
            $pubkey = '';
            $this->assertEquals(1, secp256k1_ec_pubkey_create($context, $privkey, 0, $pubkey));
            $this->assertEquals(1, secp256k1_ecdsa_verify($context, $msg, $signature, $pubkey));
        }
    }
}
