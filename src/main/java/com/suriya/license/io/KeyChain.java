package com.suriya.license.io;

import com.suriya.license.core.algorithm.AsymmetricKey;
import com.suriya.license.core.algorithm.DigiSign;
import com.suriya.license.core.algorithm.SymmetricKey;
import com.suriya.license.core.parser.AttributeParser;
import com.suriya.license.core.parser.ByteProcessor;
import com.suriya.license.core.parser.MainProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;

public final class KeyChain implements AlgorithmDefaults {

    private Info info;
    private Map<String, String> informationKeyAttributeMap;

    private KeyStore keyStore;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] signature;

    private KeyChain() {}

    private KeyChain(Info info, Map<String, String> informationKeyAttributeMap) {
        this.info = info;
        this.informationKeyAttributeMap = informationKeyAttributeMap;
    }

    private static void validate(Info info) {
    }

    public static KeyChain generate(Info info, Map<String, String> productKeyAttributeMap) {
        validate(info);
        KeyChain keyChain = new KeyChain(info, productKeyAttributeMap);
        keyChain.bindSignatureKey(keyChain.bindPublicKey(keyChain.bindProductKey()));
        return keyChain;
    }

    public static KeyChain validate(Info info, Set<String> productKeyAttributeSet) {
        KeyChain keyChain = new KeyChain();
        keyChain.validateProductKey(info, productKeyAttributeSet);
        return null;
    }

    public void deploy() {
        Path path = Paths.get(info.getFilePath() + "\\" + info.getFileName());
        try {
            Files.write(path, get());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] get() {
        return ByteProcessor.writeKeyStoreIntoByteArray(keyStore, info.getFilePassword());
    }

    private String bindProductKey() {
        Key secretProductKey = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm); //DES HmacSHA1
        String encodedProductKeyString = Base64.getEncoder().encodeToString(secretProductKey.getEncoded());
        keyStore = ByteProcessor.storeSecretKeyInKeyStore(null, keyStoreAlgorithm,
                info.getFilePassword(), secretProductKey, "infoKey",
                info.getProductPassword(),
                AttributeParser.populateAttributeSetFromMap(informationKeyAttributeMap));
        return encodedProductKeyString;
    }

    private String bindPublicKey(String encodedProductKeyString) {
        Key secretPublicKey = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm);
        String encodedPublicKeyString = Base64.getEncoder().encodeToString(secretPublicKey.getEncoded());
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(keyPairAlgorithm, keyPairKeySize);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        Map<String, String> publicKeyAttributeMap = new HashMap<>();
        publicKeyAttributeMap.put("publicKey", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        MainProcessor.storeSecretKeyInKeyStore(keyStore, keyStoreAlgorithm, info.getFilePassword(),
                secretPublicKey,  "publicKey", encodedProductKeyString, AttributeParser.populateAttributeSetFromMap(publicKeyAttributeMap));
        return encodedPublicKeyString;
    }

    private void bindSignatureKey(String encodedPublicKeyString) {
        String productKeyUniqueIdentifier = UUID.randomUUID().toString(); // TODO generate hash from productAttributes
        Key key3 = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, productKeyUniqueIdentifier);
        byte[] signature = DigiSign.sign(signAlgorithmRSA, privateKey, "data to be encrypted".getBytes(StandardCharsets.UTF_8));
        Map<String, String> signatureAttributeMap = new HashMap<>();
        signatureAttributeMap.put("signature", Base64.getEncoder().encodeToString(signature));

        MainProcessor.storeSecretKeyInKeyStore(keyStore, keyStoreAlgorithm, info.getFilePassword(), key3,  "signatureKey", encodedPublicKeyString, AttributeParser.populateAttributeSetFromMap(signatureAttributeMap));
    }



    private boolean validateProductKey(Info info, Set<String> productKeyAttributeSet) {

        return false;
    }
}
