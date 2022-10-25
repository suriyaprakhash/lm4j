package com.suriya.keychain.core;


import com.suriya.keychain.core.algorithm.Hash;
import com.suriya.keychain.core.algorithm.SymmetricKey;
import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.ByteProcessor;

import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Base64;

import static com.suriya.keychain.io.Settings.Algorithm.messageDigestAlgorithm;
import static com.suriya.keychain.io.Settings.Algorithm.passwordKeyAlgorithm;
import static com.suriya.keychain.io.Settings.General.*;
import static com.suriya.keychain.io.Settings.General.SIGNATURE_KEY;

public final class ChainValidator extends Validator {


    public static boolean validateSignature(String signatureAlgorithm,
                                            PublicKey publicKey,
                                            byte[] signature,
                                            byte[] data) {
        return false;
    }

    public String validate(KeyStore keyStore) {
        return validateSignatureKey(keyStore, validatePublicKey(keyStore, validateInfoKey(keyStore)));
    }

    public String validateInfoKey(KeyStore keyStore) {
        KeyStore.Entry secretInfoKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, INFO_KEY, info.getProductPassword());
        infoKeyAttributeMap = AttributeParser.populateAttributeMapFromSet(secretInfoKeyEntry.getAttributes(), infoKeyAttributeSet);
        Key secretInfoKey =  ByteProcessor.readSecretKeyFromKeyStore(keyStore, INFO_KEY, info.getProductPassword());
        return  Base64.getEncoder().encodeToString(secretInfoKey.getEncoded());
    }

    public String validatePublicKey(KeyStore keyStore, String encodedInfoKeyString) {
        KeyStore.Entry secretPublicKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, PUBLIC_KEY, encodedInfoKeyString);
        Key secretPublicKey = ByteProcessor.readSecretKeyFromKeyStore(keyStore, PUBLIC_KEY, encodedInfoKeyString);
        return Base64.getEncoder().encodeToString(secretPublicKey.getEncoded());
    }

    public String validateSignatureKey(KeyStore keyStore, String encodedInfoKeyString) {
        KeyStore.Entry secretSignatureKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, SIGNATURE_KEY, encodedInfoKeyString);
        Key secretSignatureKeyRead = ByteProcessor.readSecretKeyFromKeyStore(keyStore, SIGNATURE_KEY, encodedInfoKeyString);

        String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                infoKeyAttributeMap.toString()));
        Key secretSignatureKeyReGenerated = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, infoKeyUniqueIdentifier);

        return Base64.getEncoder().encodeToString(secretSignatureKeyRead.getEncoded());
    }
}
