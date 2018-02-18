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
        $data = Yaml::parse(file_get_contents(__DIR__ . '/data/signatures.yml'));

        $fixtures = array();
        $context = TestCase::getContext();
        foreach ($data['signatures'] as $vector) {
            $fixtures[] = array($context, $vector['privkey'], $vector['msg'], substr($vector['sig'], 0, -2));
            //$fixtures[] = array($context, $vector['privkey'], $vector['msg'], $vector['sig']);
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

    public function testVerifyWithInvalidInput()
    {
        $context = TestCase::getContext();
        $private = $this->pack('17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5');
        $msg32 = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $sig = $this->pack('304502206af189487988df26eb4c2b2c7d74b78e19822bbb2fc27dada0800019abd20b46022100f0e6c4dabd4970afe125f707fbd6d62e79e950bdb2b4b9700214779ae475b05d');

        /** @var resource $public */
        $public = null;
        $this->assertEquals(1, \secp256k1_ec_pubkey_create($context, $public, $private), 'public');

        /** @var resource $s */
        /** @var resource $s1 */
        $s = null;
        $s1 = null;
        $this->assertEquals(1, secp256k1_ecdsa_signature_parse_der($context, $s, $sig));
        $this->assertEquals(1, secp256k1_ecdsa_signature_normalize($context, $s1, $s));

        $this->assertEquals(1, \secp256k1_ecdsa_verify($context, $s1, $msg32, $public), 'initial check');
        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, $s1, '', $public), 'msg32 as empty string');
        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, $s1, 1, $public), 'msg32 as 1');

        /** @var resource $lax */
        $lax = null;
        $lax1 = null;
        $this->assertEquals(1, \ecdsa_signature_parse_der_lax($context, $lax, $sig));
        $this->assertEquals(1, secp256k1_ecdsa_signature_normalize($context, $lax1, $lax));

        $this->assertEquals(1, \secp256k1_ecdsa_verify($context, $lax1, $msg32, $public), 'initial check');
        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, $lax1, '', $public), 'msg32 as empty string');
        $this->assertEquals(0, \secp256k1_ecdsa_verify($context, $lax1, 1, $public), 'msg32 as 1');
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
        $sig = pack("H*", $sig);

        /** @var resource $pubkey */
        $pubkey = null;
        $this->assertEquals($ePubCreate, \secp256k1_ec_pubkey_create($context, $pubkey, $seckey));

        /** @var resource $s */
        $s = null;
        $this->assertEquals(1, secp256k1_ecdsa_signature_parse_der($context, $s, $sig));

        /** @var resource $normalSig */
        $normalSig = null;
        $normalize = secp256k1_ecdsa_signature_normalize($context, $normalSig, $s);
        if ($normalize) {
            if ($eSigCreate) {
                $this->assertEquals(0, \secp256k1_ecdsa_verify($context, $s, $msg, $pubkey));
                $this->assertEquals($eSigCreate, \secp256k1_ecdsa_verify($context, $normalSig, $msg, $pubkey));
            }
        } else {
            $this->assertEquals($eSigCreate, \secp256k1_ecdsa_verify($context, $s, $msg, $pubkey));
        }

        /** @var resource $lax */
        $lax = null;
        $this->assertEquals(1, \ecdsa_signature_parse_der_lax($context, $lax, $sig));
        if ($normalize) {
            /** @var resource $normalLax */
            secp256k1_ecdsa_signature_normalize($context, $normalLax, $s);
            $this->assertEquals(1, \secp256k1_ecdsa_verify($context, $normalLax, $msg, $pubkey));
        } else {
            $this->assertEquals(1, \secp256k1_ecdsa_verify($context, $s, $msg, $pubkey));
        }
    }
}
