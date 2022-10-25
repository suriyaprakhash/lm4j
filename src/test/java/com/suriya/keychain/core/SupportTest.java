package com.suriya.keychain.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SupportTest {
//
//    static Generator generator;
//
//    @BeforeAll
//    public static void beforeAll() {
//        generator = Generator.getSingletonGenerator();
//    }

    /**
     * Test for {@link Support#getSupportedAlgorithms(String)} using Cipher
     */
    @Test
    @DisplayName("getSupportedAlgorithms(String) using Cipher")
    public void supportedAlgorithmTest_Cipher() {
        String crypto = "Cipher";
//        System.out.println("Supported " + crypto + " Algorithms :");
        Support.getSupportedAlgorithms(crypto).forEach(System.out::println);
    }

    /**
     * Test for {@link Support#getSupportedAlgorithms(String)} using MessageDigest
     */
    @Test
    public void supportedAlgorithmTest_MessageDigest() {
        String crypto = "MessageDigest";
        System.out.println("Supported " + crypto + " Algorithms :");
        Support.getSupportedAlgorithms(crypto).forEach(System.out::println);
    }

    /**
     * Test for {@link Support#getSupportedAlgorithms(String)} using Mac
     */
    @Test
    public void supportedAlgorithmTest_Mac() {
        String crypto = "Mac";
        System.out.println("Supported " + crypto + " Algorithms :");
        Support.getSupportedAlgorithms(crypto).forEach(System.out::println);

    }

    /**
     * Test for {@link Support#getSupportedAlgorithms(String)} using KeyGenerator
     */
    @Test
    public void supportedAlgorithmTest_KeyGenerator() {
        String crypto = "KeyGenerator";
        System.out.println("Supported " + crypto + " Algorithms :");
        Support.getSupportedAlgorithms(crypto).forEach(System.out::println);

    }

    /**
     * Test for {@link Support#getSupportedAlgorithms(String)} using KeyPairGenerator
     */
    @Test
    public void supportedAlgorithmTest_KeyPairGenerator () {
        String crypto = "KeyPairGenerator";
        System.out.println("Supported " + crypto + " Algorithms :");
        Support.getSupportedAlgorithms(crypto).forEach(System.out::println);

    }



}
