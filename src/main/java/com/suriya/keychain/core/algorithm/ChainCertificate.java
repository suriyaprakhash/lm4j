package com.suriya.keychain.core.algorithm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class ChainCertificate {

    public static class RelativeDistinguishedNames {
        private String country;
        private String state;
        private String orgName;
        private String commonName;

        public RelativeDistinguishedNames(String country, String state, String orgName, String commonName) {
            this.country = country;
            this.state = state;
            this.orgName = orgName;
            this.commonName = commonName;
        }
    }

    public static Certificate build(String algorithm, KeyPair keyPair, int expiryInDays, RelativeDistinguishedNames rdn) throws
            Exception {

        // Generate a keypair
//
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(1024);
//        KeyPair keyPair = kpg.generateKeyPair();

        // Start creating a self-signed X.509 certificate with the public key

        X500Name subjName = new X500Name("C=" + rdn.country + ", ST=" + rdn.state + ", O=" + rdn.orgName
                + ", CN="+rdn.commonName);
        BigInteger serialNumber = new BigInteger("900");
        Calendar cal = Calendar.getInstance();
//        cal.set(2014, 6, 7, 11, 59, 59);
        Date notBefore = cal.getTime();
        cal.add(Calendar.DATE, expiryInDays); // Expires in 10 years
        Date notAfter = cal.getTime();
        JcaX509v3CertificateBuilder x509Builder = new JcaX509v3CertificateBuilder(subjName, serialNumber, 
                notBefore, notAfter, subjName, keyPair.getPublic());

        // Create a signer to sign (self-sign) the certificate.
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(algorithm); //"SHA256WithRSA"
        ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
//        Signature signer = Signature.getInstance("SHA256WithRSA", "BC");

        // Now finish the creation of the self-signed certificate.
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate mySelfSignedCert = converter.getCertificate(x509Builder.build(signer));

        // Now create a KeyStore and store the private key and associated cert.
//
//        final char[] password = "password99".toCharArray();
//        KeyStore ks = KeyStore.getInstance("JKS");
//        ks.load(null, password);

        KeyStore.TrustedCertificateEntry certificateEntry = new KeyStore.TrustedCertificateEntry(mySelfSignedCert);

//        KeyStore.PrivateKeyEntry privKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),
//                new Certificate[] {mySelfSignedCert});
//        ks.setEntry("myRSAkey", privKeyEntry, new KeyStore.PasswordProtection(password));

        // Now save off the KeyStore to a file.

//        FileOutputStream fos = null;
//        try {
//            fos = new FileOutputStream("MyKeys.jks");
//            ks.store(fos, password);
//        } finally {
//            if (fos != null) {
//                fos.close();
//            }
//        }

        return mySelfSignedCert;
    }
}