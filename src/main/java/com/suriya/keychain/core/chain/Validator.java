package com.suriya.keychain.core.chain;

import com.suriya.keychain.core.algorithm.DigiSign;
import com.suriya.keychain.core.algorithm.Hash;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.suriya.keychain.io.Settings.Algorithm.*;

public class Validator {

    public static boolean validateSignature(ValidationHolder validationHolder) {

        String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                validationHolder.infoKeyAttributeMap.toString()));

        return DigiSign.verify(signAlgorithm,validationHolder.publicKey, validationHolder.signature, (Base64.getEncoder().encodeToString(validationHolder.publicKey.getEncoded())
                        + infoKeyUniqueIdentifier).getBytes(StandardCharsets.UTF_8));
    }
}
