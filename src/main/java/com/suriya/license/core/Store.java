package com.suriya.license.core;

import com.suriya.license.util.ConversionUtility;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.util.HashSet;
import java.util.Set;

public class Store {

    public static String LICENSE_ID_ATTRIBUTE_NAME = "licenseId";
    public static String USER_ID_ATTRIBUTE_NAME = "userId";
    public static String HOSTNAME_ATTRIBUTE_NAME = "hostName";

    public static void storeSecretKey(String algorithm, Key key, String secretEntryAliasName,
                                      String keyStoreFolderPath, String keyStoreName, String keyStorePass) {
        storeSecretKey(algorithm, key, null, secretEntryAliasName,
                keyStoreFolderPath, keyStoreName, keyStorePass);
    }

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
            KeyStore.SecretKeyEntry secretKeyEntry = null;
            if (attributeSet != null) {
                secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key, attributeSet);
            } else {
                secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key);
            }
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


//    https://stackoverflow.com/questions/9890313/how-to-use-keystore-in-java-to-store-private-key
    public static void storeKeyPair(String algorithm, KeyPair keyPair, Set<KeyStore.Entry.Attribute> attributeSet, String secretEntryAliasName,
                                      String keyStoreFolderPath, String keyStoreName, String keyStorePass, Class privateKeySpecClass, Class publicKeySpecClass) {
        try {
            //Creating the KeyStore object
//            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
//            kpg.initialize(2048);
//
//            KeyPair kp = kpg.genKeyPair();
//
//            KeyFactory fact = KeyFactory.getInstance(algorithm);
////
//            KeySpec publicKeySpec = fact.getKeySpec(keyPair.getPublic(),
//                    publicKeySpecClass); //RSAPublicKeySpec.class
//
//            KeySpec privateKeySpec = fact.getKeySpec(keyPair.getPrivate(),
//                    privateKeySpecClass); //RSAPrivateKeySpec.class DSAPrivateKeySpec
//
//            saveToFile(keyStoreFolderPath + "//" + keyStoreName + ".pub", keyPair.getPublic());
//            saveToFile(keyStoreFolderPath + "//" + keyStoreName, keyPair.getPrivate());

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Store Public Key.
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                    publicKey.getEncoded());
            FileOutputStream fos = new FileOutputStream(keyStoreFolderPath + "//" + keyStoreName + ".pub");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();

            // Store Private Key.
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    privateKey.getEncoded());
            fos = new FileOutputStream(keyStoreFolderPath + "//" + keyStoreName);
            fos.write(pkcs8EncodedKeySpec.getEncoded());
            fos.close();

            System.out.println("data stored");

        } catch (FileNotFoundException fileNotFoundException) {
            fileNotFoundException.printStackTrace();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    private static void saveToFile(String fileName, Key key)
            throws IOException {
        DataOutputStream dout = null;
        try {
            dout = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
            dout.write(key.getEncoded());
            dout.flush();
        } catch (Exception e) {
            throw e;
        } finally {
            dout.close();
        }
    }


    public static KeyPair readKeyPairFromKeyStore(String algorithm, String keyStoreFolderPath, String keyStoreName) {
        KeyPair keyPair = null;
        try {

            File privateKeyFile = new File(keyStoreFolderPath + "//" + keyStoreName);
            File publicKeyFile = new File(keyStoreFolderPath + "//" + keyStoreName);

            FileInputStream privateFis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);
            FileInputStream publicFis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName + ".pub");

            byte[] privateKeyByteArray = new byte[(int) privateKeyFile.length()];
            byte[] publicKeyByteArray = new byte[(int) publicKeyFile.length()];

            privateFis.read(privateKeyByteArray);
            privateFis.close();

            publicFis.read(publicKeyByteArray);
            publicFis.close();

            // Generate KeyPair.
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    publicKeyByteArray);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                    privateKeyByteArray);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            keyPair = new KeyPair(publicKey, privateKey);

        } catch (NoSuchAlgorithmException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return keyPair;
    }


    public static KeyPair loadKeyPair(String algorithm, String keyStoreFolderPath, String keyStoreName)
         {
             PublicKey publicKey = null;
             PrivateKey privateKey = null;
             try {
                 // Read Public Key.
                 File filePublicKey = new File(keyStoreFolderPath + "//" + keyStoreName + ".pub");
                 FileInputStream fis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName + ".pub");
                 byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
                 fis.read(encodedPublicKey);
                 fis.close();

                 // Read Private Key.
                 File filePrivateKey = new File(keyStoreFolderPath + "//" + keyStoreName);
                 fis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);
                 byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
                 fis.read(encodedPrivateKey);
                 fis.close();

                 // Generate KeyPair.
                 KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                 X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                         encodedPublicKey);
                  publicKey = keyFactory.generatePublic(publicKeySpec);

                 PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                         encodedPrivateKey);
                  privateKey = keyFactory.generatePrivate(privateKeySpec);
             } catch (FileNotFoundException e) {
                 e.printStackTrace();
             } catch (IOException e) {
                 e.printStackTrace();
             } catch (NoSuchAlgorithmException e) {
                 e.printStackTrace();
             } catch (InvalidKeySpecException e) {
                 e.printStackTrace();
             }

             return new KeyPair(publicKey, privateKey);
    }
}
