package com.suriya.license.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class ConversionUtility {

    public static String bytesToHex(byte[] inputBytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : inputBytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static String stringToHex(String inputString) {
        byte[] byteString = inputString.getBytes(Charset.forName("UTF-8"));
        BigInteger biStr = new BigInteger(byteString);
        return biStr.toString(16);
    }

    public static String stringToBinary(String inputString) {
        byte[] byteString = inputString.getBytes(Charset.forName("UTF-8"));
        BigInteger biStr = new BigInteger(byteString);
        return biStr.toString(2);
    }

    public static String stringToDecimal(String inputString) {
        byte[] byteString = inputString.getBytes(Charset.forName("UTF-8"));
        BigInteger biStr = new BigInteger(byteString);
        return biStr.toString(10);
    }

    public static ASN1ObjectIdentifier stringToASN1(String inputString) {
        return ASN1ObjectIdentifier.fromContents(inputString.getBytes(StandardCharsets.UTF_8));
    }

}
