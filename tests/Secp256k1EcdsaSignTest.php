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
        $data = Yaml::parse(file_get_contents(__DIR__ . '/data/deterministicSignatures.yml'));

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

        /** @var resource $signature */
        $signature = null;
        $sign = secp256k1_ecdsa_sign($context, $signature, $msg, $privkey);

        $this->assertEquals($eSigCreate, $sign);
        $this->assertEquals(SECP256K1_TYPE_SIG, get_resource_type($signature));

        $normalized = null;
        secp256k1_ecdsa_signature_normalize($context, $normalized, $signature);

        $sigSerOut = null;
        $this->assertEquals(1, secp256k1_ecdsa_signature_serialize_der($context, $sigSerOut, $normalized));
        $this->assertEquals($expectedSig, unpack("H*", $sigSerOut)[1]);
    }
}
