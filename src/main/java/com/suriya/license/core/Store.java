package com.suriya.license.core;

import com.suriya.license.util.ConversionUtility;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

public class Store {

    public static String LICENSE_ID_ATTRIBUTE_NAME = "licenseId";
    public static String USER_ID_ATTRIBUTE_NAME = "userId";
    public static String HOSTNAME_ATTRIBUTE_NAME = "hostName";

    public static void storeSecretKey(String algorithm, Key key, Set<KeyStore.Entry.Attribute> attributeSet, String secretEntryAliasName,
                                      String keyStoreFolderPath, String keyStoreName, String keyStorePass) {
        try {
            //Creating the KeyStore object
            KeyStore keyStore = KeyStore.getInstance(algorithm);  //JCEKS PKCS12

            //Loading the KeyStore object
            char[] password = keyStorePass.toCharArray(); // changeit
//            String path = "C:/Program Files/Java/jre1.8.0_101/lib/security/cacerts";
//            java.io.FileInputStream fis = new FileInputStream(keyStoreFolderPath);
//            keyStore.load(fis, password);
            keyStore.load(null, password);

            //Creating the KeyStore.ProtectionParameter object
            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password);

            //Creating SecretKeyEntry object
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key, attributeSet);
            keyStore.setEntry(secretEntryAliasName, secretKeyEntry, protectionParam); //"secretKeyAlias"

            //Storing the KeyStore object
            File file = new File(keyStoreFolderPath+"//"+keyStoreName);
            java.io.FileOutputStream fos = new java.io.FileOutputStream(file);
            keyStore.store(fos, password);
            System.out.println("data stored");

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static KeyStore.Entry readKeyStoreEntryFromKeyStore(String algorithm, String secretEntryAliasName,
                                                   String keyStoreFolderPath, String keyStoreName, String keyStorePass) {
        KeyStore.Entry keyStoreEntry = null;
        try {
            KeyStore ks = KeyStore.getInstance(algorithm);
            FileInputStream fis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);

            ks.load(fis, keyStorePass.toCharArray());
            SecretKey secretKey = (SecretKey) ks.getKey(secretEntryAliasName, keyStorePass.toCharArray());

            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keyStorePass.toCharArray());
            keyStoreEntry = ks.getEntry(secretEntryAliasName,protectionParam);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyStoreEntry;
    }

    public static SecretKey readSecretKeyFromKeyStore(String algorithm, String secretKeyAliasName,
                                                   String keyStoreFolderPath, String keyStoreName, String keyStorePass) {
        SecretKey secretKey = null;
        try {
            KeyStore ks = KeyStore.getInstance(algorithm);
            FileInputStream fis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);

            ks.load(fis, keyStorePass.toCharArray());
            secretKey = (SecretKey) ks.getKey(secretKeyAliasName, keyStorePass.toCharArray());

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return secretKey;
    }

    public static Set<KeyStore.Entry.Attribute> getAttributesSet(String licenseId, String userId, String hostName) {
        Set<KeyStore.Entry.Attribute> attributeSet = new HashSet<>();
        if (licenseId != null) {
            KeyStore.Entry.Attribute licenseIdAttr = null;
            licenseIdAttr = new PKCS12Attribute(ConversionUtility.stringToASN1(LICENSE_ID_ATTRIBUTE_NAME).toString(), licenseId);
//          licenseIdAttr = new PKCS12Attribute(new ASN1ObjectIdentifier("licenseId".getBytes(StandardCharsets.UTF_8), false).getId(), userId);
            attributeSet.add(licenseIdAttr);
        }
        if (userId != null) {
            KeyStore.Entry.Attribute userIdAttr = new PKCS12Attribute(ASN1ObjectIdentifier.fromContents(USER_ID_ATTRIBUTE_NAME.getBytes(StandardCharsets.UTF_8)).toString(), userId);
            attributeSet.add(userIdAttr);
        }
        KeyStore.Entry.Attribute hostNameAttr =  new PKCS12Attribute(ASN1ObjectIdentifier.fromContents(HOSTNAME_ATTRIBUTE_NAME.getBytes(StandardCharsets.UTF_8)).toString(), hostName);
        attributeSet.add(hostNameAttr);

        return attributeSet;
    }
}
