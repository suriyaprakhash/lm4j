package com.suriya.license.util;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

public class CertificateBuilder {
//
//    class Certificate {
//        public String issuer;
//        public String subject;
//    }


    /**
     * Generate V3 Certificate.
     * @param issuer issuer
     * @param subject subject
     * @param useForServerAuth use for server auth flag
     * @param useForClientAuth use for client auth flag
     * @param subjectAltName subject alt name
     * @param subjectIPAssress subject IP address
     * @param publicKey public key
     * @param privateKey private key
     * @param from certificate validity first date
     * @param to certificate validity last date
     * @param signatureAlgorithm signature algorithm
     * @return X509Certificate object
     * @throws GeneralSecurityException GeneralSecurityException
     */
    public static X509Certificate generateV3Certificate(X500Principal issuer, X500Principal subject,
                                                        boolean useForServerAuth, boolean useForClientAuth,
                                                        String subjectAltName, String subjectIPAssress, PublicKey publicKey, PrivateKey privateKey,
                                                        Date from, Date to, String signatureAlgorithm) throws GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder();

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

//            public X509v3CertificateBuilder(X500Name var1, BigInteger var2, Time var3, Time var4, X500Name var5, SubjectPublicKeyInfo var6) {
//            this.tbsGen = new V3TBSCertificateGenerator();
//            this.tbsGen.setSerialNumber(new ASN1Integer(var2));
//            this.tbsGen.setIssuer(var1);
//            this.tbsGen.setStartDate(var3);
//            this.tbsGen.setEndDate(var4);
//            this.tbsGen.setSubject(var5);
//            this.tbsGen.setSubjectPublicKeyInfo(var6);
//            this.extGenerator = new ExtensionsGenerator();
//        }

        certGen.setSerialNumber(new BigInteger(UUID.randomUUID().toString().replaceAll("-", ""), 16));
        certGen.setSubjectDN(subject);
        certGen.setIssuerDN(issuer);
        certGen.setNotBefore(from);
        certGen.setNotAfter(to);
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm(signatureAlgorithm);

        /*
        certGen.addExtension(X509Extensions.BasicConstraints, true, issuer.equals(subject) ? new BasicConstraints(1) : new BasicConstraints(false));
        if (!issuer.equals(subject)) {
            certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                    | KeyUsage.keyEncipherment | (useForServerAuth ? KeyUsage.keyCertSign | KeyUsage.cRLSign : 0)));
        }
        if (useForServerAuth) {
            certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        }
        if (useForClientAuth) {
            certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        }
        if (subjectAltName != null) {
            certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
                    new GeneralName(GeneralName.rfc822Name, subjectAltName)));
        }
        if (subjectIPAssress != null) {
            certGen.addExtension(X509Extensions.SubjectAlternativeName, true, new GeneralNames(
                    new GeneralName(GeneralName.iPAddress, subjectIPAssress)));
        }
        */
        return certGen.generate(privateKey);
    }
}
