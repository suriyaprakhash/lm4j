package com.suriya.keychain.core.algorithm;

import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.cert.Certificate;

public class ChainCertificateTest {

    @Test
    public void chainCertBuildTest() throws Exception {
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey("RSA", 2048);
        ChainCertificate.RelativeDistinguishedNames rdn = new ChainCertificate
                .RelativeDistinguishedNames("USA", "NY", "org", "suriya");
        Certificate cert = ChainCertificate.build("SHA256WithRSA", keyPair, 10, rdn);
        try {
            cert.verify(keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
