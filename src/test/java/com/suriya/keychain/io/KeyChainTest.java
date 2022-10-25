package com.suriya.keychain.io;

import com.suriya.keychain.core.Support;
import com.suriya.license.io.Info;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
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

        Map<String, String> headerMap = new HashMap<>();
        headerMap.put("generator", "keyChain");

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

//        System.out.println(keyChain.get());
//        System.out.println(keyChain.get().length);
//        keyChain.deploy();


    }
}
