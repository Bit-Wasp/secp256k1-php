<?php

namespace BitWasp\Secp256k1Tests;

class Secp256k1ConstantsTest extends TestCase
{
    public function testConstants()
    {
        $this->assertEquals('secp256k1_ecdsa_signature_t', SECP256K1_TYPE_SIG);
        $this->assertEquals('secp256k1_ecdsa_recoverable_signature_t', SECP256K1_TYPE_RECOVERABLE_SIG);
        $this->assertEquals('secp256k1_pubkey_t', SECP256K1_TYPE_PUBKEY);
        $this->assertEquals('secp256k1_context_t', SECP256K1_TYPE_CONTEXT);

        $this->assertEquals('1', SECP256K1_CONTEXT_VERIFY);
        $this->assertEquals('2', SECP256K1_CONTEXT_SIGN);
    }
}