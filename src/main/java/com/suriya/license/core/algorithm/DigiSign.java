package com.suriya.license.core.algorithm;

import java.security.*;

public final class DigiSign {

    public static byte[] sign(String signatureAlgorithm, PrivateKey privateKey, String data) {
        byte[] signature = null;
        try {
            //Creating a Signature object
            Signature sign = Signature.getInstance(signatureAlgorithm); //SHA256withDSA

            //Initializing the signature
            sign.initSign(privateKey);
            byte[] bytes = data.getBytes();

            //Adding data to the signature
            sign.update(bytes);

            //Calculating the signature
            signature = sign.sign();

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return signature;
    }

    public static boolean verify(String signatureAlgorithm, PublicKey publicKey, byte[] signature, String data) {
        boolean verified = false;
        try {
            //Creating a Signature object
            Signature sign = Signature.getInstance(signatureAlgorithm); //SHA256withDSA

            //Initializing the signature
            sign.initVerify(publicKey);
            sign.update(data.getBytes());

            verified = sign.verify(signature);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return verified;
    }

}
