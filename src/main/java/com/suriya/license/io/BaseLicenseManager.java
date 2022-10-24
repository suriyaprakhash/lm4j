package com.suriya.license.io;

import java.util.Map;

public abstract class BaseLicenseManager {
    String productKeyAlgorithm = "HmacSHA256";
    String productKeyFileAlgorithm = "PKCS12";
    String digitalSignatureAlgorithm = "RSA";
    int SIGNATURE_KEY_SIZE = 2048;


}
