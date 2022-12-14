package com.suriya.keychain.core.parser;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.util.*;

public class FileProcessor {


    /**
     * This method stores the keystore into the file system
     *
     * @param keyStoreAlgorithm - algorithm for the key store
     * @param key - the key itself
     * @param attributeSet - set of attributes to be added as part of the key entry
     * @param secretEntryAliasName - alias name for the key
     * @param secretPassword - password for the key
     * @param keyStoreFolderPath - file system path to store the keystore
     * @param keyStoreName - filename of the keystore file to be saved
     * @param keyStorePassword - password to be used for accessing the key store
     */
    public static void storeSecretKeyInKeyStore(String keyStoreAlgorithm, Key key,
                                                Set<KeyStore.Entry.Attribute> attributeSet,
                                                String secretEntryAliasName, String secretPassword,
                                                String keyStoreFolderPath, String keyStoreName,
                                                String keyStorePassword) {
        try {
            // getting the algorithm
            KeyStore keyStore = KeyStore.getInstance(keyStoreAlgorithm);  //JCEKS PKCS12

            char[] keyStorePassCharArray = keyStorePassword.toCharArray(); // changeit
            char[] secretEntryPassCharArray = secretPassword.toCharArray();

            // initializing the empty stream for new keystore / existing keystore would need inputStream
            keyStore.load(null, keyStorePassCharArray);

            // the protection param is used to protect the secret entry
            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(secretEntryPassCharArray);

            KeyStore.SecretKeyEntry secretKeyEntry = null;

            if (attributeSet != null) {
                secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key, attributeSet);
            } else {
                secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key);
            }

            // adding the entry to the keystore
            keyStore.setEntry(secretEntryAliasName, secretKeyEntry, protectionParam); //"secretKeyAlias"

            //Storing the KeyStore object
            File file = new File(keyStoreFolderPath+"//"+keyStoreName);
            java.io.FileOutputStream fos = new java.io.FileOutputStream(file);
            keyStore.store(fos, keyStorePassCharArray);

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

    public static KeyStore.Entry readKeyStoreEntryFromKeyStore(String algorithm, String secretEntryAliasName,String secretEntryPass,
                                                   String keyStoreFolderPath, String keyStoreName, String keyStorePass) {
        KeyStore.Entry keyStoreEntry = null;
        try {
            KeyStore ks = KeyStore.getInstance(algorithm);
            FileInputStream fis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);

            ks.load(fis, keyStorePass.toCharArray());
            SecretKey secretKey = (SecretKey) ks.getKey(secretEntryAliasName, secretEntryPass.toCharArray());

            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(secretEntryPass.toCharArray());
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

    public static SecretKey readSecretKeyFromKeyStore(String algorithm, String secretKeyAliasName, String secretEntryPass,
                                                   String keyStoreFolderPath, String keyStoreName, String keyStorePass) {
        SecretKey secretKey = null;
        try {
            KeyStore ks = KeyStore.getInstance(algorithm);
            FileInputStream fis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);

            ks.load(fis, keyStorePass.toCharArray());
            secretKey = (SecretKey) ks.getKey(secretKeyAliasName, secretEntryPass.toCharArray());

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

    //    https://stackoverflow.com/questions/9890313/how-to-use-keystore-in-java-to-store-private-key
    public static void storeKeyPair(KeyPair keyPair,
                                      String keyStoreFolderPath, String keyStoreName) {
        try {
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


//    private static void saveToFile(String fileName, Key key)
//            throws IOException {
//        DataOutputStream dout = null;
//        try {
//            dout = new DataOutputStream(
//                new BufferedOutputStream(new FileOutputStream(fileName)));
//            dout.write(key.getEncoded());
//            dout.flush();
//        } catch (Exception e) {
//            throw e;
//        } finally {
//            dout.close();
//        }
//    }

//
//    public static KeyPair readKeyPairFromKeyStore(String algorithm, String keyStoreFolderPath, String keyStoreName) {
//        KeyPair keyPair = null;
//        try {
//
//            File privateKeyFile = new File(keyStoreFolderPath + "//" + keyStoreName);
//            File publicKeyFile = new File(keyStoreFolderPath + "//" + keyStoreName);
//
//            FileInputStream privateFis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName);
//            FileInputStream publicFis = new FileInputStream(keyStoreFolderPath + "//" + keyStoreName + ".pub");
//
//            byte[] privateKeyByteArray = new byte[(int) privateKeyFile.length()];
//            byte[] publicKeyByteArray = new byte[(int) publicKeyFile.length()];
//
//            privateFis.read(privateKeyByteArray);
//            privateFis.close();
//
//            publicFis.read(publicKeyByteArray);
//            publicFis.close();
//
//            // Generate KeyPair.
//            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
//            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
//                    publicKeyByteArray);
//            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
//
//            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
//                    privateKeyByteArray);
//            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
//
//            keyPair = new KeyPair(publicKey, privateKey);
//
//        } catch (NoSuchAlgorithmException | FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//        return keyPair;
//    }
//

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
