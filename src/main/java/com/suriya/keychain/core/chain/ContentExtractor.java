package com.suriya.keychain.core.chain;


import com.suriya.keychain.core.algorithm.Hash;
import com.suriya.keychain.core.algorithm.SymmetricKey;
import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static com.suriya.keychain.io.Settings.Algorithm.*;
import static com.suriya.keychain.io.Settings.General.*;

public final class ContentExtractor extends Extractor {

    public ContentExtractor(ValidationHolder validationHolder) {
        super(validationHolder);
    }

    public String extract(KeyStore keyStore) {
        return validateSignatureKey(keyStore, validatePublicKey(keyStore, validateInfoKey(keyStore)));
    }

    public String validateInfoKey(KeyStore keyStore) {
        KeyStore.Entry secretInfoKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, INFO_KEY, validationHolder.info.getProductPassword());
        validationHolder.infoKeyAttributeMap = AttributeParser.populateAttributeMapFromSet(secretInfoKeyEntry.getAttributes(), validationHolder.infoKeyAttributeSet);
        Key secretInfoKey =  ByteProcessor.readSecretKeyFromKeyStore(keyStore, INFO_KEY, validationHolder.info.getProductPassword());
        return  Base64.getEncoder().encodeToString(secretInfoKey.getEncoded());
    }

    public String validatePublicKey(KeyStore keyStore, String encodedInfoKeyString) {
        KeyStore.Entry secretPublicKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, PUBLIC_KEY, encodedInfoKeyString);

        validationHolder.publicKey = extractPublicKey(secretPublicKeyEntry);

        Key secretPublicKey = ByteProcessor.readSecretKeyFromKeyStore(keyStore, PUBLIC_KEY, encodedInfoKeyString);
        return Base64.getEncoder().encodeToString(secretPublicKey.getEncoded());
    }

    public String validateSignatureKey(KeyStore keyStore, String encodedInfoKeyString) {
        KeyStore.Entry secretSignatureKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, SIGNATURE_KEY, encodedInfoKeyString);
        Key secretSignatureKeyRead = ByteProcessor.readSecretKeyFromKeyStore(keyStore, SIGNATURE_KEY, encodedInfoKeyString);

        validationHolder.signature = extractSignature(secretSignatureKeyEntry);

        String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                validationHolder.infoKeyAttributeMap.toString()));
        Key secretSignatureKeyReGenerated = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, infoKeyUniqueIdentifier);

        return Base64.getEncoder().encodeToString(secretSignatureKeyRead.getEncoded());
    }

    private PublicKey extractPublicKey(KeyStore.Entry secretPublicKeyEntry) {
        Set<String> publicKeyAttributeSetRead = new HashSet();
        publicKeyAttributeSetRead.add(PUBLIC_KEY);
        String publicKeyStringRead = AttributeParser.populateAttributeMapFromSet(secretPublicKeyEntry.getAttributes(),
                publicKeyAttributeSetRead).get(PUBLIC_KEY);
        PublicKey publicKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    Base64.getDecoder().decode(publicKeyStringRead.getBytes(StandardCharsets.UTF_8)));
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    private byte[] extractSignature(KeyStore.Entry secretSignatureKeyEntry) {
        Set<String> signatureKeyAttributeSetRead = new HashSet();
        signatureKeyAttributeSetRead.add(SIGNATURE_KEY);
        return Base64.getDecoder().decode(AttributeParser.populateAttributeMapFromSet(secretSignatureKeyEntry.getAttributes(),
                signatureKeyAttributeSetRead).get(SIGNATURE_KEY));
    }


}
