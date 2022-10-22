package com.suriya.license.core.algorithm;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class MessageAuthenticationCode {

    /**
     * MAC
     *
     * Message Authentication Code (MAC) using JCA
     *
     * CLIENT: mac(message) * SymmetricKey = Client.MAC/HMAC
     * SERVER: mac(message) * SymmetricKey = Server.MAC/HMAC
     * VALIDATION: SERVER checks if Client.MAC/HMAN == Server.MAC/HMAC
     *
     * @param message
     * @return
     */
    public static byte[] generateMAC(String macAlgorithm, Key key, String message) {
//        String macResultString = null;
        byte[] macResult = null;
        try {
            //Creating a Mac object
            Mac mac = Mac.getInstance(macAlgorithm); //HmacSHA256

            //Initializing the Mac object
            mac.init(key);

            //Computing the Mac
            byte[] bytes = message.getBytes();
            macResult = mac.doFinal(bytes);

        }
        catch (InvalidKeyException | NoSuchAlgorithmException e) { //  mac.init(key)
            e.printStackTrace();
        }
        return macResult;
    }

    public static String getStringFromMacByteArray(byte[] mac) {
        //mac.toString();
        return new String(mac);
    }

}
