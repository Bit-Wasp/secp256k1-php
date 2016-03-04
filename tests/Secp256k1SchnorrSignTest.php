<?php

namespace BitWasp\Secp256k1Tests;


class Secp256k1SchnorrSignTest extends TestCase
{
    public function testEndtoEnd()
    {
        $context = TestCase::getContext();

        $priv1 = str_pad('', 32, "\x02");
        /** @var resource $pub1 */
        /** @var resource $pub2 */
        $pub1 = '';

        $priv2 = str_pad('', 32, "\x90");
        $pub2 = '';

        secp256k1_ec_pubkey_create($context, $priv1, $pub1);
        secp256k1_ec_pubkey_create($context, $priv2, $pub2);



    }
}