package com.suriya.keychain.core.chain;

import com.suriya.keychain.core.algorithm.DigiSign;
import com.suriya.keychain.core.algorithm.Hash;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.suriya.keychain.io.Settings.Algorithm.messageDigestAlgorithm;
import static com.suriya.keychain.io.Settings.Algorithm.signAlgorithm;

public class Validator {
    public static boolean validateSignature(ExtractorStorage extractorStorage) {

        String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                extractorStorage.infoKeyAttributeMap.toString()));

        return DigiSign.verify(signAlgorithm, extractorStorage.publicKey, extractorStorage.signature, (Base64.getEncoder().encodeToString(extractorStorage.publicKey.getEncoded())
                + infoKeyUniqueIdentifier).getBytes(StandardCharsets.UTF_8));
    }
}
