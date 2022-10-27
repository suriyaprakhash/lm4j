package com.suriya.keychain.core.chain;


import com.suriya.keychain.core.algorithm.DigiSign;
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

public final class ChainExtractor extends Extractor {

    public ChainExtractor(ExtractorStorage extractorStorage) {
        super(extractorStorage);
    }

    public String extract(KeyStore keyStore) {
        return validateSignatureKey(keyStore, validatePublicKey(keyStore, validateInfoKey(keyStore)));
    }

    public String validateInfoKey(KeyStore keyStore) {
        KeyStore.Entry secretInfoKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, INFO_KEY, extractorStorage.info.getProductPassword());
        extractorStorage.infoKeyAttributeMap = AttributeParser.populateAttributeMapFromSet(secretInfoKeyEntry.getAttributes(), extractorStorage.infoKeyAttributeSet);
        Key secretInfoKey =  ByteProcessor.readSecretKeyFromKeyStore(keyStore, INFO_KEY, extractorStorage.info.getProductPassword());
        return  Base64.getEncoder().encodeToString(secretInfoKey.getEncoded());
    }

    public String validatePublicKey(KeyStore keyStore, String encodedInfoKeyString) {
        KeyStore.Entry secretPublicKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, PUBLIC_KEY, encodedInfoKeyString);

        extractorStorage.publicKey = extractPublicKey(secretPublicKeyEntry);

        Key secretPublicKey = ByteProcessor.readSecretKeyFromKeyStore(keyStore, PUBLIC_KEY, encodedInfoKeyString);
        return Base64.getEncoder().encodeToString(secretPublicKey.getEncoded());
    }

    public String validateSignatureKey(KeyStore keyStore, String encodedInfoKeyString) {
        KeyStore.Entry secretSignatureKeyEntry = ByteProcessor.readKeyStoreEntryOfSecretKeyFromKeyStore(keyStore, SIGNATURE_KEY, encodedInfoKeyString);
        Key secretSignatureKeyRead = ByteProcessor.readSecretKeyFromKeyStore(keyStore, SIGNATURE_KEY, encodedInfoKeyString);

        extractorStorage.signature = extractSignature(secretSignatureKeyEntry);

        String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                extractorStorage.infoKeyAttributeMap.toString()));
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
