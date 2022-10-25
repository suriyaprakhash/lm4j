package com.suriya.license.io;

public abstract class Settings {
    static String keyStoreAlgorithm = "PKCS12";
    static String secureRandomKeyAlgorithm = "HmacSHA1";
    static String passwordKeyAlgorithm = "HmacSHA1";
    static String keyPairAlgorithm = "RSA";
    static String signAlgorithmRSA = "SHA256withRSA";
    static int keyPairKeySize = 2048;

    static String INFO_KEY = "infoKey";
    static String PUBLIC_KEY = "publicKey";
    static String SIGNATURE_KEY = "signatureKey";

    public static String getKeyStoreAlgorithm() {
        return keyStoreAlgorithm;
    }

    public static void setKeyStoreAlgorithm(String keyStoreAlgorithm) {
        Settings.keyStoreAlgorithm = keyStoreAlgorithm;
    }

    public static String getSecureRandomKeyAlgorithm() {
        return secureRandomKeyAlgorithm;
    }

    public static void setSecureRandomKeyAlgorithm(String secureRandomKeyAlgorithm) {
        Settings.secureRandomKeyAlgorithm = secureRandomKeyAlgorithm;
    }

    public static String getPasswordKeyAlgorithm() {
        return passwordKeyAlgorithm;
    }

    public static void setPasswordKeyAlgorithm(String passwordKeyAlgorithm) {
        Settings.passwordKeyAlgorithm = passwordKeyAlgorithm;
    }

    public static String getKeyPairAlgorithm() {
        return keyPairAlgorithm;
    }

    public static void setKeyPairAlgorithm(String keyPairAlgorithm) {
        Settings.keyPairAlgorithm = keyPairAlgorithm;
    }

    public static String getSignAlgorithmRSA() {
        return signAlgorithmRSA;
    }

    public static void setSignAlgorithmRSA(String signAlgorithmRSA) {
        Settings.signAlgorithmRSA = signAlgorithmRSA;
    }

    public static int getKeyPairKeySize() {
        return keyPairKeySize;
    }

    public static void setKeyPairKeySize(int keyPairKeySize) {
        Settings.keyPairKeySize = keyPairKeySize;
    }

    public static String getInfoKey() {
        return INFO_KEY;
    }

    public static void setInfoKey(String infoKey) {
        INFO_KEY = infoKey;
    }

    public static String getPublicKey() {
        return PUBLIC_KEY;
    }

    public static void setPublicKey(String publicKey) {
        PUBLIC_KEY = publicKey;
    }

    public static String getSignatureKey() {
        return SIGNATURE_KEY;
    }

    public static void setSignatureKey(String signatureKey) {
        SIGNATURE_KEY = signatureKey;
    }
}
