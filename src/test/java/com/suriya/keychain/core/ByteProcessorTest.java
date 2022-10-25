package com.suriya.keychain.core;

import com.suriya.keychain.core.algorithm.AsymmetricKey;
import com.suriya.keychain.core.algorithm.DigiSign;
import com.suriya.keychain.core.algorithm.SymmetricKey;
import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.ByteProcessor;
import com.suriya.license.io.Info;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ByteProcessorTest {

    @Test
    public void fullTest1() throws NoSuchAlgorithmException, InvalidKeySpecException {

        String keyStoreAlgorithm = "PKCS12";
        String secureRandomKeyAlgorithm = "HmacSHA1";
        String passwordKeyAlgorithm = "HmacSHA1";
        String keyPairAlgorithm = "RSA";
        String signAlgorithmRSA = "SHA256withRSA";
        int keyPairKeySize = 2048;

        String productName = "product1";
        String productPassword = "suriya"; // generate using hash -> eg. hostName, userId or whatever using MD5

        String filePath = "src//test//resources//store";
        String fileName = "ite2elocalgen";
        String filePassword = "suriyafile"; // generate using hash -> eg. hostName, userId or whatever using MD5

        Map<String, String> productKeyAttributeMap = new LinkedHashMap<>();
        productKeyAttributeMap.put("licenseId", "lic123");
        productKeyAttributeMap.put("userId", "user1");
        productKeyAttributeMap.put("dod", "deliveryDate");
        productKeyAttributeMap.put("dope", "prodExpDate");

        Info info = new Info();
        info.setProductName(productName);
        info.setProductPassword(productPassword);

        info.setFilePath(filePath);
        info.setFileName(fileName);
        info.setFilePassword(filePassword);

        // KEY 1
        // WRITE
        Key key1 = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm); //DES HmacSHA1
        String encodedKeyString1 = Base64.getEncoder().encodeToString(key1.getEncoded());
        KeyStore keyStore1 = ByteProcessor.keyStoreFromKeyStoreByteArray(null, keyStoreAlgorithm, filePassword);
        ByteProcessor.storeSecretKeyInKeyStore(keyStore1, keyStoreAlgorithm, filePassword, key1,  "productKey", productPassword, AttributeParser.populateAttributeSetFromMap(productKeyAttributeMap));
        byte[] keyStoreByteArray1 = ByteProcessor.writeKeyStoreIntoByteArray(keyStore1, filePassword);
        System.out.println("keyStoreByteArray1.length: "+keyStoreByteArray1.length);

        // READ
        KeyStore keyStore1Read = ByteProcessor.readKeyStoreFromByteArray(keyStoreByteArray1, keyStoreAlgorithm, filePassword);
        KeyStore.Entry keyStoreEntry1Read = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore1Read, "productKey", productPassword);
        Key key1Read =  ByteProcessor.readSecretKeyFromKeyStore(keyStore1Read, "productKey", productPassword);
        String encodedKeyString1Read = Base64.getEncoder().encodeToString(key1Read.getEncoded());
        Assertions.assertEquals(encodedKeyString1, encodedKeyString1Read);

        // KEY 2
        // WRITE
        Key key2 = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm);
        String encodedKeyString2 = Base64.getEncoder().encodeToString(key2.getEncoded());
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(keyPairAlgorithm, keyPairKeySize);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, String> publicKeyAttributeMap = new HashMap<>();
        publicKeyAttributeMap.put("publicKey", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        KeyStore keyStore2 = ByteProcessor.keyStoreFromKeyStoreByteArray(keyStoreByteArray1, keyStoreAlgorithm, filePassword);
        ByteProcessor.storeSecretKeyInKeyStore(keyStore2, keyStoreAlgorithm, filePassword, key2,  "publicKey", encodedKeyString1, AttributeParser.populateAttributeSetFromMap(publicKeyAttributeMap));
        byte[] keyStoreByteArray2 = ByteProcessor.writeKeyStoreIntoByteArray(keyStore2, filePassword);
        System.out.println("keyStoreByteArray2.length: "+keyStoreByteArray2.length);

        // READ
        KeyStore keyStore2Read = ByteProcessor.readKeyStoreFromByteArray(keyStoreByteArray2, keyStoreAlgorithm, filePassword);
        KeyStore.Entry keyStoreEntry2Read = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore2Read, "publicKey", encodedKeyString1);
        Key key2Read =  ByteProcessor.readSecretKeyFromKeyStore(keyStore2Read, "publicKey", encodedKeyString1);
        String encodedKeyString2Read = Base64.getEncoder().encodeToString(key2Read.getEncoded());
        Assertions.assertEquals(encodedKeyString2, encodedKeyString2Read);

        Set<String> publicKeyAttributeSetRead = new HashSet<String>();
        publicKeyAttributeSetRead.add("publicKey");
        publicKeyAttributeSetRead.add("familyName");
        Map<String, String> publicKeyAttributeMapRead = AttributeParser.populateAttributeMapFromSet(keyStoreEntry2Read.getAttributes(), publicKeyAttributeSetRead);
        String publicKeyStringRead = publicKeyAttributeMapRead.get("publicKey");

        KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                Base64.getDecoder().decode(publicKeyStringRead.getBytes(StandardCharsets.UTF_8)));
        PublicKey publicKeyRead = keyFactory.generatePublic(publicKeySpec);
        Assertions.assertEquals(publicKey, publicKeyRead);

        // KEY 3
        // WRITE
        String productKeyUniqueIdentifier = UUID.randomUUID().toString(); // TODO generate hash from productAttributes
        Key key3 = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, productKeyUniqueIdentifier);
        byte[] signature = DigiSign.sign(signAlgorithmRSA, privateKey, Base64.getEncoder().encodeToString(key1.getEncoded()).getBytes(StandardCharsets.UTF_8));
        Map<String, String> signatureAttributeMap = new HashMap<>();
        signatureAttributeMap.put("signature", Base64.getEncoder().encodeToString(signature));

        KeyStore keyStore3 = ByteProcessor.keyStoreFromKeyStoreByteArray(keyStoreByteArray2, keyStoreAlgorithm, filePassword);
        ByteProcessor.storeSecretKeyInKeyStore(keyStore3, keyStoreAlgorithm, filePassword, key3,  "signatureKey", encodedKeyString2, AttributeParser.populateAttributeSetFromMap(signatureAttributeMap));
        byte[] keyStoreByteArray3 = ByteProcessor.writeKeyStoreIntoByteArray(keyStore3, filePassword);
        System.out.println("keyStoreByteArray3.length: "+keyStoreByteArray3.length);

        // write file name with productKeyUniqueIdentifier

        // READ
        KeyStore keyStore3Read = ByteProcessor.readKeyStoreFromByteArray(keyStoreByteArray3, keyStoreAlgorithm, filePassword);
        Key key3regenerated = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, productKeyUniqueIdentifier);
        Key key3Read = ByteProcessor.readSecretKeyFromKeyStore(keyStore3Read, "signatureKey", encodedKeyString2);
        KeyStore.Entry keyStoreEntry3Read = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore3Read, "signatureKey", encodedKeyString2);

        Set<String> signatureAttributeSetRead = new HashSet<String>();
        signatureAttributeSetRead.add("signature");
        Map<String, String> signatureAttributeMapRead = AttributeParser.populateAttributeMapFromSet(keyStoreEntry3Read.getAttributes(), signatureAttributeSetRead);
        byte[] signatureRead = Base64.getDecoder().decode(signatureAttributeMapRead.get("signature"));
        Assertions.assertTrue(DigiSign.verify(signAlgorithmRSA, publicKeyRead, signatureRead, Base64.getEncoder().encodeToString(key1Read.getEncoded()).getBytes(StandardCharsets.UTF_8)));
        Assertions.assertTrue(Arrays.equals(key3regenerated.getEncoded(), key3Read.getEncoded())); // MATCHES THE KEY GENERATION & SECRET KEY
    }
}
