package com.suriya.license.io;

import com.suriya.license.core.algorithm.Hash;
import com.suriya.license.util.ConversionUtility;

import java.util.List;

public abstract class BasePasswordGenerator {

    String hashAlgorithm = "SHA-256";

    public String generateHashedPassword(List<String> inputList) {
        byte[] hash = Hash.generateMessageDigest(hashAlgorithm, inputList.stream()
                .reduce("", (output, currentString) -> output + currentString));
        return Hash.getHexStringFromByteArray(hash);
    }

    public String generateHashedObjectIdentifier(String input) {
        return ConversionUtility.stringToASN1(input).toString();
    }
}
