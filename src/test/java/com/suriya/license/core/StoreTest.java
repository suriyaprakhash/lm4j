package com.suriya.license.core;

import com.suriya.license.core.algorithm.AsymmetricKey;
import com.suriya.license.core.algorithm.SymmetricKey;
import com.suriya.license.util.ConversionUtility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Set;

public class StoreTest {

    /**
     * Manual test using : keytool -list -v -keystore randomSecretKey
     */
    @Test
    public void storeKey_Test_randomSecretKey() throws KeyStoreException {
        String keyStorePass = "suriya";
        String keyGenAlgorithm = "HmacSHA256";
        String keyStoreGenAlgorithm = "PKCS12";
        String secretKeyAliasName = "secretKeyAlias";
        String keyStoreFilePath = "src//test//resources//store";
        String keyStoreFileName = "randomSecretKey";

        String licenseIdAttributeValue = "lic123";
        String userIdAttributeValue = "user1";
        String hostNameAttributeValue = "host1";

        // Store Keystore
        Key key = SymmetricKey.generateSecureRandomKey(keyGenAlgorithm); //DES HmacSHA1
        String generatedSecretMessage = new String(key.getEncoded());
        Set<KeyStore.Entry.Attribute> attributeSet = Store.getAttributesSet(licenseIdAttributeValue, userIdAttributeValue, hostNameAttributeValue);
        Store.storeSecretKey(keyStoreGenAlgorithm, key, attributeSet, secretKeyAliasName, keyStoreFilePath,keyStoreFileName,  keyStorePass); //JCEKS PKCS12

        // Read from keyStore and validate
        // here keyStoreEntry has secretKey in case of asymetric key it will have private/public key
        KeyStore.Entry keyStoreEntry = Store.readKeyStoreEntryFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        SecretKey secretKey = Store.readSecretKeyFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        Set<KeyStore.Entry.Attribute> attributeSetReadFromTheEntry = keyStoreEntry.getAttributes();

        // Validate entry
        String licenseIdASN1 = ConversionUtility.stringToASN1(Store.LICENSE_ID_ATTRIBUTE_NAME).toString();
        String userIdASN1 = ConversionUtility.stringToASN1(Store.USER_ID_ATTRIBUTE_NAME).toString();
        String hostNameASN1 = ConversionUtility.stringToASN1(Store.HOSTNAME_ATTRIBUTE_NAME).toString();
        KeyStore.Entry.Attribute licenseIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(licenseIdASN1)).findAny().get();
        KeyStore.Entry.Attribute userIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(userIdASN1)).findAny().get();
        KeyStore.Entry.Attribute hostNameAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(hostNameASN1)).findAny().get();
        Assertions.assertEquals(licenseIdAttributeValue, licenseIdAttribute.getValue());
        Assertions.assertEquals(userIdAttributeValue, userIdAttribute.getValue());
        Assertions.assertEquals(hostNameAttributeValue, hostNameAttribute.getValue());

        // Validate secret key
        String secretKeyMessageReadFromTheKey = new String(secretKey.getEncoded());
        Assertions.assertEquals(generatedSecretMessage, secretKeyMessageReadFromTheKey);
    }

    /**
     * Manual test using : keytool -list -v -keystore mySecretKey
     */
    @Test
    public void storeKey_Test_secretFromPassword() throws KeyStoreException {
        String secretKeyPassword = "mySecret";
        String keyStorePass = "suriya";
        String keyGenAlgorithm = "HmacSHA256";
        String keyStoreGenAlgorithm = "PKCS12";
        String secretKeyAliasName = "secretKeyAlias";
        String keyStoreFilePath = "src//test//resources//store";
        String keyStoreFileName = "mySecretKey";

        String licenseIdAttributeValue = "lic456";
        String userIdAttributeValue = "user2";
        String hostNameAttributeValue = "host2";

        // Store Keystore
        Key key = SymmetricKey.generateKeyFromPassword(keyGenAlgorithm, secretKeyPassword); //DES HmacSHA1
        Set<KeyStore.Entry.Attribute> attributeSet = Store.getAttributesSet(licenseIdAttributeValue, userIdAttributeValue, hostNameAttributeValue);
        Store.storeSecretKey(keyStoreGenAlgorithm, key, attributeSet, secretKeyAliasName, keyStoreFilePath,keyStoreFileName,  keyStorePass); //JCEKS PKCS12

        // Read from keyStore and validate
        // here keyStoreEntry has secretKey in case of asymetric key it will have private/public key
        KeyStore.Entry keyStoreEntry = Store.readKeyStoreEntryFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        SecretKey secretKey = Store.readSecretKeyFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        Set<KeyStore.Entry.Attribute> attributeSetReadFromTheEntry = keyStoreEntry.getAttributes();

        // Validate entry
        String licenseIdASN1 = ConversionUtility.stringToASN1(Store.LICENSE_ID_ATTRIBUTE_NAME).toString();
        String userIdASN1 = ConversionUtility.stringToASN1(Store.USER_ID_ATTRIBUTE_NAME).toString();
        String hostNameASN1 = ConversionUtility.stringToASN1(Store.HOSTNAME_ATTRIBUTE_NAME).toString();
        KeyStore.Entry.Attribute licenseIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(licenseIdASN1)).findAny().get();
        KeyStore.Entry.Attribute userIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(userIdASN1)).findAny().get();
        KeyStore.Entry.Attribute hostNameAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(hostNameASN1)).findAny().get();
        Assertions.assertEquals(licenseIdAttributeValue, licenseIdAttribute.getValue());
        Assertions.assertEquals(userIdAttributeValue, userIdAttribute.getValue());
        Assertions.assertEquals(hostNameAttributeValue, hostNameAttribute.getValue());

        // Validate secret key
        String secretKeyMessageReadFromTheKey = new String(secretKey.getEncoded());
        Assertions.assertEquals(secretKeyPassword, secretKeyMessageReadFromTheKey);
//        System.out.println(new BigInteger(1, secretKey.getEncoded()).toString(16));

    }

    /**
     * Manual test using : keytool -list -v -keystore randomSecretKey
     */
    @Test
    public void storeKey_Test_keyPair() throws KeyStoreException {
        String keyPairGenAlgorithm = "DSA"; //DSA RSA
//        String keyStoreGenAlgorithm = "PKCS12"; //DSA RSA
        String keyAliasName = "privateKeyAlias";
        String keyStoreFilePath = "src//test//resources//store";
        String keyStoreFileName = "keyPair";
        String keyStorePass = "suriya";

//        String publicKeyStoreFilePath = "src//test//resources//store";
//        String publicKeyStoreFileName = "publicKey.pub";
//        String publicKeyStorePass = "suriya";

        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(keyPairGenAlgorithm);
//        PrivateKey privateKey = keyPair.getPrivate();
//        PublicKey publicKey = keyPair.getPublic();

        Store.storeKeyPair(keyPairGenAlgorithm, keyPair, null, keyAliasName,
                keyStoreFilePath, keyStoreFileName,  keyStorePass, RSAPrivateKeySpec.class, RSAPublicKeySpec.class);
        Store.loadKeyPair(keyPairGenAlgorithm, keyStoreFilePath, keyStoreFileName);
    }
}
