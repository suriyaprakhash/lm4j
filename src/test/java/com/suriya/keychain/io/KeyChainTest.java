package com.suriya.keychain.io;

import com.suriya.license.io.Info;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class KeyChainTest {

    @Test
    public void testKeyChainCreate() {
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



        Map<String, String> headerMap = new HashMap<>();
        headerMap.put("generator", "keyChain");
        headerMap.put("testValue1", "testValue1Ans");
        headerMap.put("testValue2", "testValue2Ans");

        Settings.General.INFO_KEY = "deltadataKey";
        Settings.General.saveGeneratedKeyStore = true;

        Info info = new Info();
        info.setProductName(productName);
        info.setProductPassword(productPassword);

        info.setFilePath(filePath);
        info.setFileName(fileName);
        info.setFilePassword(filePassword);

        KeyChain.Generator generator = KeyChain.generate(info, productKeyAttributeMap, headerMap);
        generator.deploy();

        System.out.println(generator.getHeader().length);
        System.out.println(generator.getBody().length);


        /////////////////////////////////////////////////////////////

        Set<String> productKeyAttributeSet = productKeyAttributeMap.keySet();

        boolean verified = KeyChain.verify(info, productKeyAttributeSet);


    }

    @Test
    public void testKeyChainVerify() {

        String productName = "product1";
        String productPassword = "suriya"; // generate using hash -> eg. hostName, userId or whatever using MD5

        String filePath = "src//test//resources//store";
        String fileName = "keyChain";
        String filePassword = "suriyafile"; // generate using hash -> eg. hostName, userId or whatever using MD5

        Settings.General.INFO_KEY = "deltadataKey";
        Info info = new Info();
        info.setProductName(productName);
        info.setProductPassword(productPassword);

        info.setFilePath(filePath);
        info.setFileName(fileName);
        info.setFilePassword(filePassword);

        Map<String, String> productKeyAttributeMap = new LinkedHashMap<>();
        productKeyAttributeMap.put("licenseId", "lic123");
        productKeyAttributeMap.put("userId", "user1");
        productKeyAttributeMap.put("dod", "deliveryDate");
        productKeyAttributeMap.put("dope", "prodExpDate");

        Set<String> productKeyAttributeSet = productKeyAttributeMap.keySet();

        boolean verified = KeyChain.verify(info, productKeyAttributeSet);
    }


}
