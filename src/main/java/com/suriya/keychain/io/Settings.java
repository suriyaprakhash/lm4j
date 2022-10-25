package com.suriya.keychain.io;

public class Settings {

    public static class General {
        public static String INFO_KEY = "infoKey";
        public static String PUBLIC_KEY = "publicKey";
        public static String SIGNATURE_KEY = "signatureKey";

        public static boolean saveGeneratedKeyStore = false;
        public static boolean saveGeneratedPrivateKey = true;
    }

    public static class ContentFormat {
        public static int determinedHeaderLengthStoreByteCapacity = 4;
        public static int headerByteCapacity = 256;
    }

    public static class Algorithm {
        public static String keyStoreAlgorithm = "PKCS12";
        public static String secureRandomKeyAlgorithm = "HmacSHA1";
        public static String passwordKeyAlgorithm = "HmacSHA1";
        public static String keyPairAlgorithm = "RSA";
        public static String signAlgorithm = "SHA256withRSA";
        public static String messageDigestAlgorithm ="SHA-256";
        public static int keyPairKeySize = 2048;
    }

}
