package com.suriya.license.core.algorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {

    /**
     * MESSAGE DIGEST
     *
     * Hash always produces same output for the given input.
     *
     * iteration-1 : md(message) = 12345
     * iteration-2 : md(message) = 12345
     * iteration-3 : md(message1) = 23456 // different message produce different outcome
     * iteration-4 : md(message) = 12345
     *
     * This is not reversible. Used to validate the given password is correct or not against any stored value. Since the
     * given input can only generate one output.
     *
     * @param message
     * @return
     */
    public static byte[] generateMessageDigest(String algorithm, String message) {

        byte[] digest = null;
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm); //"SHA-256"

            //Passing data to the created MessageDigest Object
            md.update(message.getBytes());

            //Compute the message digest
            digest = md.digest(); // or md.digest(message.getBytes())

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest;
    }

    public static String getHexStringFromByteArray(byte[] digest) {
        //Converting the byte array in to HexString format
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }

        return hexString.toString();
    }
}
