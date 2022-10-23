package com.suriya.license.io;

import com.suriya.license.core.algorithm.SymmetricKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class LicenseManagerTest {

    @Test
    public void end2endTest_LocalGeneration() {
        String productName = "product1";
        String productPassword = "suriya"; // generate using hash -> eg. hostName, userId or whatever using MD5

        String filePath = "src//test//resources//store";
        String fileName = "ite2elocalgen";
        String filePassword = "suriyafile"; // generate using hash -> eg. hostName, userId or whatever using MD5

        Map<String, String> attributeMap = new LinkedHashMap<>();
        attributeMap.put("licenseId", "lic123");
        attributeMap.put("userId", "user1");
        attributeMap.put("dod", "deliveryDate");
        attributeMap.put("dope", "prodExpDate");

        ProductKey productKey = new ProductKey();
        productKey.setProductName(productName);
        productKey.setProductPassword(productPassword);

        productKey.setFilePath(filePath);
        productKey.setFileName(fileName);
        productKey.setFilePassword(filePassword);


        LicenseManager licenseManager = LicenseManager.getInstance();
        licenseManager.generate(productKey, attributeMap);

        Set<String> keys = new HashSet<>(attributeMap.keySet());
//        keys.add("hello");
        Map<String, String> attributeMapReadFromTheStoreEntry = licenseManager.readAttributeMap(productKey, keys);
        Assertions.assertTrue(attributeMapReadFromTheStoreEntry.equals(attributeMap));
    }

    @Test
    public void end2endTest_ProviderDistribution() {

    }
}
