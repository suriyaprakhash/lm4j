package com.suriya.license.core.algorithm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Key;

public class SymmetricKeyTest {

    /**
     *  Test for {@link com.suriya.license.core.algorithm.SymmetricKey#generateSecureRandomKey(String)}  with DES
     */
    @Test
    public void generateSecureRandomKeyTest_DES() {
        System.out.println("Key with DES :");
        System.out.println("MAC : " + com.suriya.license.core.algorithm.SymmetricKey.generateSecureRandomKey("DES"));
    }
    @Test
    public void generateSecureRandomKeyTest_DES_NotSameOnDifferentIterations() {
        System.out.println("Key with DES :");
        System.out.println("MAC : " + com.suriya.license.core.algorithm.SymmetricKey.generateSecureRandomKey("DES"));
        Key iteration1 = com.suriya.license.core.algorithm.SymmetricKey.generateSecureRandomKey("DES");
        Key iteration2 = com.suriya.license.core.algorithm.SymmetricKey.generateSecureRandomKey("DES");
        Assertions.assertTrue(!iteration1.equals(iteration2));
    }


    /**
     *  Test for {@link com.suriya.license.core.algorithm.SymmetricKey#generateKeyFromPassword(String, String)}  with DER
     */
    @Test
    public void generateKeyFromPasswordTest_DER_SameForSamePassword() {
        System.out.println("Key with DER :");
        System.out.println("MAC : " + com.suriya.license.core.algorithm.SymmetricKey.generateKeyFromPassword("DER", "Suriya"));
        Key iteration1 = com.suriya.license.core.algorithm.SymmetricKey.generateKeyFromPassword("DER", "Suriya");
        Key iteration2 = com.suriya.license.core.algorithm.SymmetricKey.generateKeyFromPassword("DER", "Suriya");
        Assertions.assertTrue(iteration1.equals(iteration2));
    }


    /**
     *  Test for {@link com.suriya.license.core.algorithm.SymmetricKey#generateKeyFromPasswordBasedEncryption(String, String)} with PBEWithSHA1AndDESede
     */
    @Test
    public void generateKeyFromPasswordBasedEncryptionTest_DER_SameForSamePassword() {
        System.out.println("Key with DER :");
        System.out.println("MAC : " + com.suriya.license.core.algorithm.SymmetricKey.generateKeyFromPasswordBasedEncryption("PBEWithSHA1AndDESede", "Suriya"));
        Key iteration1 = com.suriya.license.core.algorithm.SymmetricKey.generateKeyFromPasswordBasedEncryption("PBEWithSHA1AndDESede", "Suriya");
        Key iteration2 = com.suriya.license.core.algorithm.SymmetricKey.generateKeyFromPasswordBasedEncryption("PBEWithSHA1AndDESede", "Suriya");
        Assertions.assertTrue(iteration1.equals(iteration2));
    }
}
