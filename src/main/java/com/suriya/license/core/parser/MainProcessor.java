//package com.suriya.license.core.parser;
//
//import javax.crypto.SecretKey;
//import java.security.Key;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.util.Set;
//
//public class MainProcessor {
//
//    public static void storeSecretKeyInKeyStore(KeyStore keyStore, String keyStoreAlgorithm, String keyStorePass, Key key,
//                                                    String secretKeyEntryAliasName, String secretPassword,
//                                                    Set<KeyStore.Entry.Attribute> attributeSet) {
//
//        try {
//            //Creating the KeyStore.ProtectionParameter object
//            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(secretPassword.toCharArray());
//
//            //Creating SecretKeyEntry object
//            KeyStore.SecretKeyEntry secretKeyEntry = null;
//            if (attributeSet != null) {
//                secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key, attributeSet);
//            } else {
//                secretKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) key);
//            }
//            keyStore.setEntry(secretKeyEntryAliasName, secretKeyEntry, protectionParam); //"secretKeyAlias"
//
////            //Storing the KeyStore object
////            ByteArrayOutputStream out = new ByteArrayOutputStream();
////            keyStore.store(out, keyStorePasswordCharArray);
////            updatedKeyStoreByteArray = new byte[out.size()];
////            System.out.println(out.size());
////            updatedKeyStoreByteArray = out.toByteArray();
////
////            out.close();
//
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//    }
//}
