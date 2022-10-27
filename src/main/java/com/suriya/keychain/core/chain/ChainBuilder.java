package com.suriya.keychain.core.chain;

import com.suriya.keychain.core.algorithm.AsymmetricKey;
import com.suriya.keychain.core.algorithm.DigiSign;
import com.suriya.keychain.core.algorithm.Hash;
import com.suriya.keychain.core.algorithm.SymmetricKey;
import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.suriya.keychain.io.Settings.Algorithm.*;
import static com.suriya.keychain.io.Settings.General.*;
import static com.suriya.keychain.io.Settings.General.SIGNATURE_KEY;

public class ChainBuilder extends Builder {

    public ChainBuilder(BuilderStorage builderStorage) {
        super(builderStorage);
    }

    public void connect() {
        KeyStore keyStore = null;
        bindSignatureKey(bindPublicKey(bindProductKey()));
    }

    private String bindProductKey() {
        Key secretProductKey = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm); //DES HmacSHA1
        String encodedProductKeyString = Base64.getEncoder().encodeToString(secretProductKey.getEncoded());
        builderStorage.keyStore = ByteProcessor.keyStoreFromKeyStoreByteArray(null, keyStoreAlgorithm,
                builderStorage.info.getFilePassword());
        ByteProcessor.storeSecretKeyInKeyStore(builderStorage.keyStore, keyStoreAlgorithm, builderStorage.info.getFilePassword(), secretProductKey,
                INFO_KEY, builderStorage.info.getProductPassword(),
                AttributeParser.populateAttributeSetFromMap(builderStorage.infoKeyAttributeMap));
        return encodedProductKeyString;
    }

    private String bindPublicKey(String encodedProductKeyString) {
        Key secretPublicKey = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm);
        String encodedPublicKeyString = Base64.getEncoder().encodeToString(secretPublicKey.getEncoded());
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(keyPairAlgorithm, keyPairKeySize);
        builderStorage.privateKey = keyPair.getPrivate();
        builderStorage.publicKey = keyPair.getPublic();
        Map<String, String> publicKeyAttributeMap = new HashMap<>();
        publicKeyAttributeMap.put(PUBLIC_KEY, Base64.getEncoder().encodeToString(builderStorage.publicKey.getEncoded()));
        ByteProcessor.storeSecretKeyInKeyStore(builderStorage.keyStore, keyStoreAlgorithm, builderStorage.info.getFilePassword(),
                secretPublicKey, PUBLIC_KEY, encodedProductKeyString, AttributeParser.populateAttributeSetFromMap(publicKeyAttributeMap));
        return encodedPublicKeyString;
    }

    private void bindSignatureKey(String encodedPublicKeyString) {
        String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                builderStorage. infoKeyAttributeMap.toString()));
        Key secretSignatureKey = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, infoKeyUniqueIdentifier);
        builderStorage.signature = DigiSign.sign(signAlgorithm, builderStorage.privateKey,
                (Base64.getEncoder().encodeToString(builderStorage.publicKey.getEncoded())
                + infoKeyUniqueIdentifier).getBytes(StandardCharsets.UTF_8));
        Map<String, String> signatureAttributeMap = new HashMap<>();
        signatureAttributeMap.put(SIGNATURE_KEY, Base64.getEncoder().encodeToString(builderStorage.signature));

        ByteProcessor.storeSecretKeyInKeyStore(builderStorage.keyStore, keyStoreAlgorithm, builderStorage.info.getFilePassword(), secretSignatureKey,  SIGNATURE_KEY, encodedPublicKeyString, AttributeParser.populateAttributeSetFromMap(signatureAttributeMap));
    }
}
