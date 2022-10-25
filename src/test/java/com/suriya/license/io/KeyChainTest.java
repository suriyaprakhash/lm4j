package com.suriya.license.io;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

public class KeyChainTest {

    @Test
    public void testKeyChainFull() {
        String productName = "product1";
        String productPassword = "suriya"; // generate using hash -> eg. hostName, userId or whatever using MD5

        String filePath = "src//test//resources//store";
        String fileName = "keyChain";
        String filePassword = "suriyafile"; // generate using hash -> eg. hostName, userId or whatever using MD5

        Map<String, String> productKeyAttributeMap = new LinkedHashMap<>();
        productKeyAttributeMap.put("licenseId", "lic123");
        productKeyAttributeMap.put("userId", "user1");
        productKeyAttributeMap.put("dod", "deliveryDate");
        productKeyAttributeMap.put("dope", "prodExpDate");

        Settings.setInfoKey("mydataKey");

        Info info = new Info();
        info.setProductName(productName);
        info.setProductPassword(productPassword);

        info.setFilePath(filePath);
        info.setFileName(fileName);
        info.setFilePassword(filePassword);

        KeyChain keyChain = KeyChain.generate(info, productKeyAttributeMap);
        System.out.println(keyChain.get());
        System.out.println(keyChain.get().length);
        keyChain.deploy();
    }
}
