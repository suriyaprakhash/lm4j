package com.suriya.keychain.core.algorithm;

import com.suriya.license.util.ConversionUtility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.Arrays;

public class MessageAuthenticationCodeTest {


    /**
     *  Test for {@link MessageAuthenticationCode#generateMAC(String, java.security.Key, String)} with DES && HmacSHA256
     */
    @Test
    public void generateMac_HmacSHA256() {
        Key key =  SymmetricKey.generateSecureRandomKey("DES");
        byte[] iteration1 = MessageAuthenticationCode.generateMAC("HmacSHA256" , key,"Suriya");
        byte[] iteration2 = MessageAuthenticationCode.generateMAC("HmacSHA256" , key,"Suriya");
        // check byte array matches
        Assertions.assertTrue(Arrays.equals(iteration1, iteration2));
        // with hex conversion
        Assertions.assertEquals(ConversionUtility.bytesToHex(iteration1), ConversionUtility.bytesToHex(iteration2));
    }

}
