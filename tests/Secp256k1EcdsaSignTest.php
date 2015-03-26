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
            $fixtures[] = [$vector['privkey'], $vector['msg'], substr($vector['sig'], 0, strlen($vector['sig'])-2)];
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

        $signature = '';
        $sign = secp256k1_ecdsa_sign($msg, $privkey, $signature);
        $this->assertEquals($eSigCreate, $sign);
        $this->assertEquals($expectedSig, bin2hex($signature));
        
        return;

        if ($eSigCreate == 1) {
            $pubkey = '';
            $this->assertEquals(1, secp256k1_ec_pubkey_create($privkey, 0, $pubkey));
            $this->assertEquals(1, secp256k1_ecdsa_verify($msg, $signature, $pubkey));
        }
    }
}
