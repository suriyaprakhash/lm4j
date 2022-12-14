package com.suriya.keychain.core.parser;

import com.suriya.keychain.core.algorithm.AsymmetricKey;
import com.suriya.keychain.core.algorithm.SymmetricKey;
import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.FileProcessor;
import com.suriya.license.util.ConversionUtility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Set;

public class FileProcessorTest {

    /**
     * Manual test using : keytool -list -v -keystore randomSecretKey
     */
    @Test
    public void storeKey_Test_randomSecretKey() throws KeyStoreException {
//        String keyStorePass = UUID.randomUUID().toString();//"8c60064a-66fd-4bd4-9c76-fd8034188a02"
        String keyStorePass = "suriya";
        String secretKeyPassword = "suriya";
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
        String generatedKeySecretMessage = new String(key.getEncoded());
        Set<KeyStore.Entry.Attribute> attributeSet = AttributeParser.populateAttributeSetFromMap(licenseIdAttributeValue, userIdAttributeValue, hostNameAttributeValue);
        FileProcessor.storeSecretKeyInKeyStore(keyStoreGenAlgorithm, key, attributeSet, secretKeyAliasName, keyStorePass, keyStoreFilePath,keyStoreFileName,  keyStorePass); //JCEKS PKCS12

        // Read from keyStore and validate
        // here keyStoreEntry has secretKey in case of asymetric key it will have private/public key
        KeyStore.Entry keyStoreEntry = FileProcessor.readKeyStoreEntryFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName,secretKeyPassword, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        SecretKey secretKey = FileProcessor.readSecretKeyFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName,secretKeyPassword, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        Set<KeyStore.Entry.Attribute> attributeSetReadFromTheEntry = keyStoreEntry.getAttributes();

        // Validate entry
        String licenseIdASN1 = ConversionUtility.stringToASN1(AttributeParser.LICENSE_ID_ATTRIBUTE_NAME).toString();
        String userIdASN1 = ConversionUtility.stringToASN1(AttributeParser.USER_ID_ATTRIBUTE_NAME).toString();
        String hostNameASN1 = ConversionUtility.stringToASN1(AttributeParser.HOSTNAME_ATTRIBUTE_NAME).toString();
        KeyStore.Entry.Attribute licenseIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(licenseIdASN1)).findAny().get();
        KeyStore.Entry.Attribute userIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(userIdASN1)).findAny().get();
        KeyStore.Entry.Attribute hostNameAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(hostNameASN1)).findAny().get();
        Assertions.assertEquals(licenseIdAttributeValue, licenseIdAttribute.getValue());
        Assertions.assertEquals(userIdAttributeValue, userIdAttribute.getValue());
        Assertions.assertEquals(hostNameAttributeValue, hostNameAttribute.getValue());

        // Validate secret key
        String secretKeyMessageReadFromTheKey = new String(secretKey.getEncoded());
        Assertions.assertEquals(generatedKeySecretMessage, secretKeyMessageReadFromTheKey);
    }

    /**
     * Manual test using : keytool -list -v -keystore mySecretKey
     */
    @Test
    public void storeKey_Test_secretFromPassword() throws KeyStoreException {
//        String secretKeyPassword = UUID.randomUUID().toString();//"8c60064a-66fd-4bd4-9c76-fd8034188a02"
        String secretKeyPassword = "suriya";
        String keyStorePass = "suriya";
        String keySecretMessage = "hello"; //secretKey message part of key

        String keyGenAlgorithm = "HmacSHA256";
        String keyStoreGenAlgorithm = "PKCS12";
        String secretKeyAliasName = "secretKeyAlias";
        String keyStoreFilePath = "src//test//resources//store";
        String keyStoreFileName = "mySecretKey";

        String licenseIdAttributeValue = "lic456";
        String userIdAttributeValue = "user2";
        String hostNameAttributeValue = "host2";

        // Store Keystore
        Key key = SymmetricKey.generateSecretKeyFromPassword(keyGenAlgorithm, keySecretMessage); //DES HmacSHA1
        Set<KeyStore.Entry.Attribute> attributeSet = AttributeParser.populateAttributeSetFromMap(licenseIdAttributeValue, userIdAttributeValue, hostNameAttributeValue);
        FileProcessor.storeSecretKeyInKeyStore(keyStoreGenAlgorithm, key, attributeSet, secretKeyAliasName, keyStorePass, keyStoreFilePath,keyStoreFileName,  keyStorePass); //JCEKS PKCS12

        // Read from keyStore and validate
        // here keyStoreEntry has secretKey in case of asymetric key it will have private/public key
        KeyStore.Entry keyStoreEntry = FileProcessor.readKeyStoreEntryFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName,secretKeyPassword, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        SecretKey secretKey = FileProcessor.readSecretKeyFromKeyStore(keyStoreGenAlgorithm, secretKeyAliasName,secretKeyPassword, keyStoreFilePath,keyStoreFileName,  keyStorePass);
        Set<KeyStore.Entry.Attribute> attributeSetReadFromTheEntry = keyStoreEntry.getAttributes();

        // Validate entry
        String licenseIdASN1 = ConversionUtility.stringToASN1(AttributeParser.LICENSE_ID_ATTRIBUTE_NAME).toString();
        String userIdASN1 = ConversionUtility.stringToASN1(AttributeParser.USER_ID_ATTRIBUTE_NAME).toString();
        String hostNameASN1 = ConversionUtility.stringToASN1(AttributeParser.HOSTNAME_ATTRIBUTE_NAME).toString();
        KeyStore.Entry.Attribute licenseIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(licenseIdASN1)).findAny().get();
        KeyStore.Entry.Attribute userIdAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(userIdASN1)).findAny().get();
        KeyStore.Entry.Attribute hostNameAttribute = attributeSetReadFromTheEntry.stream().filter(attribute -> attribute.getName().equals(hostNameASN1)).findAny().get();
        Assertions.assertEquals(licenseIdAttributeValue, licenseIdAttribute.getValue());
        Assertions.assertEquals(userIdAttributeValue, userIdAttribute.getValue());
        Assertions.assertEquals(hostNameAttributeValue, hostNameAttribute.getValue());

        // Validate secret key
        String secretKeyMessageReadFromTheKey = new String(secretKey.getEncoded());
        Assertions.assertEquals(keySecretMessage, secretKeyMessageReadFromTheKey);
//        System.out.println(new BigInteger(1, secretKey.getEncoded()).toString(16));

    }

    /**
     * Manual test using : keytool -list -v -keystore randomSecretKey
     */
    @Test
    public void storeKey_Test_keyPair() throws KeyStoreException {
        String keyPairGenAlgorithm = "RSA"; //DSA RSA
        String keyStoreGenAlgorithm = "PKCS12"; //DSA RSA
        String keyAliasName = "privateKeyAlias";
        String keyStoreFilePath = "src//test//resources//store";
        String keyStoreFileName = "rsakeyPair";
//        String keyStorePass = UUID.randomUUID().toString();//"8c60064a-66fd-4bd4-9c76-fd8034188a02"
        String keyStorePass = "suriya";

//        String publicKeyStoreFilePath = "src//test//resources//store";
//        String publicKeyStoreFileName = "publicKey.pub";
//        String publicKeyStorePass = "suriya";

        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(keyPairGenAlgorithm, 2048);
//        PrivateKey privateKey = keyPair.getPrivate();
//        PublicKey publicKey = keyPair.getPublic();

        FileProcessor.storeKeyPair(keyPair,
                keyStoreFilePath, keyStoreFileName);
        FileProcessor.loadKeyPair(keyPairGenAlgorithm, keyStoreFilePath, keyStoreFileName);
    }

}
