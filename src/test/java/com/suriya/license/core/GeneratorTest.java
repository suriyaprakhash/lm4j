package com.suriya.license.core;

import com.suriya.license.core.algorithm.Hash;
import com.suriya.license.core.algorithm.MessageAuthenticationCode;
import com.suriya.license.core.algorithm.SymmetricKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;

public class GeneratorTest {
//
//    static Generator generator;
//
//    @BeforeAll
//    public static void beforeAll() {
//        generator = Generator.getSingletonGenerator();
//    }

    /**
     * Test for {@link Generator#getSupportedAlgorithms(String)} using Cipher
     */
    @Test
    @DisplayName("getSupportedAlgorithms(String) using Cipher")
    public void supportedAlgorithmTest_Cipher() {
        String crypto = "Cipher";
//        System.out.println("Supported " + crypto + " Algorithms :");
        Generator.getSupportedAlgorithms(crypto).forEach(System.out::println);
    }

    /**
     * Test for {@link Generator#getSupportedAlgorithms(String)} using MessageDigest
     */
    @Test
    public void supportedAlgorithmTest_MessageDigest() {
        String crypto = "MessageDigest";
        System.out.println("Supported " + crypto + " Algorithms :");
        Generator.getSupportedAlgorithms(crypto).forEach(System.out::println);
    }

    /**
     * Test for {@link Generator#getSupportedAlgorithms(String)} using Mac
     */
    @Test
    public void supportedAlgorithmTest_Mac() {
        String crypto = "Mac";
        System.out.println("Supported " + crypto + " Algorithms :");
        Generator.getSupportedAlgorithms(crypto).forEach(System.out::println);

    }



}
