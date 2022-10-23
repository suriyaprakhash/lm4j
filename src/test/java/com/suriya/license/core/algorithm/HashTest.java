package com.suriya.license.core.algorithm;

import com.suriya.license.core.algorithm.Hash;
import com.suriya.license.util.ConversionUtility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class HashTest {

    /**
     * Test for {@link Hash#generateMessageDigest(String, String)} with SHA256
     */
    @Test
    public void generateMessageDigest_SHA256() {
        System.out.println("Message digest with SHA-256 :");
        byte[] iteration1 = Hash.generateMessageDigest("SHA-256", "Suriya");
        byte[] iteration2 = Hash.generateMessageDigest("SHA-256", "Suriya");
        // check byte array matches
        Assertions.assertTrue(Arrays.equals(iteration1, iteration2));
        // with hex conversion
        Assertions.assertEquals(ConversionUtility.bytesToHex(iteration1), ConversionUtility.bytesToHex(iteration2));
    }
}
