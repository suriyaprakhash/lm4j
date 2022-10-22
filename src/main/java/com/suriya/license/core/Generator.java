package com.suriya.license.components;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.*;

public class Generator {

    private static Generator generator;

    private Generator() {
    }

    public static Generator getSingletonGenerator() {
        if (generator == null) {
            generator = new Generator();
        }
        return generator;
    }

    public String generateMessageDigest(String message) {

        String hexMessage = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            //Passing data to the created MessageDigest Object
            md.update(message.getBytes());

            //Compute the message digest
            byte[] digest = md.digest();

            //Converting the byte array in to HexString format
            StringBuffer hexString = new StringBuffer();

            for (int i = 0;i<digest.length;i++) {
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }
//            System.out.println("Hex format : " + hexString.toString());

            hexMessage = hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hexMessage;
    }

    /**
     * Message Authentication Code (MAC) using JCA
     *
     * @param message
     * @return
     */
    public String generateMAC(String message) {
        String macResultString = null;

        try {
            //Creating a KeyGenerator object
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");

            //Creating a SecureRandom object
            SecureRandom secRandom = new SecureRandom();

            //Initializing the KeyGenerator
            keyGen.init(secRandom);

            //Creating/Generating a key
            Key key = keyGen.generateKey();
            System.out.println("MAC - Key : " + key.toString() + ", algm : " + key.getAlgorithm() + ", format : "+ key.getFormat());
            System.out.println("MAC - Key : " + new String(key.getEncoded()));

            //Creating a Mac object
            Mac mac = Mac.getInstance("HmacSHA256");

            //Initializing the Mac object
            mac.init(key);

            //Computing the Mac
            byte[] bytes = message.getBytes();
            byte[] macResult = mac.doFinal(bytes);

            macResultString = new String(macResult);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) { //  mac.init(key)
            e.printStackTrace();
        }

        return macResultString;

    }

}
