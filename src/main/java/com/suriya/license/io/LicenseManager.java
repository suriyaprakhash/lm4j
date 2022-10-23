package com.suriya.license.io;

import com.suriya.license.core.Store;
import com.suriya.license.core.algorithm.AsymmetricKey;
import com.suriya.license.core.algorithm.DigiSign;
import com.suriya.license.core.algorithm.SymmetricKey;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public final class LicenseManager extends BaseLicenseManager {

    private static LicenseManager licenseManager;

    private LicenseManager() {}

    public static LicenseManager getInstance() {
        if (licenseManager == null) {
            licenseManager = new LicenseManager();
        }
        return licenseManager;
    }


    private void validateInput(ProductKey productKey) {

    }


    private void massageInput(ProductKey productKey) {
        // if key password missing, file password is used for key
        if (productKey.getProductPassword() == null) {
            productKey.setProductPassword(productKey.getFilePassword());
        }
    }

    public String generate(ProductKey productKey, Map<String, String> attributeMap) {

        validateInput(productKey);

        massageInput(productKey);

        // ProductKeyFile generation
        Key secureProductKey = SymmetricKey.generateSecureRandomKey(productKeyAlgorithm);
        Store.storeSecretKey(productKeyFileAlgorithm, secureProductKey, Store.populateAttributeSetFromMap(attributeMap),
                productKey.getProductName(), productKey.getProductPassword(),
                productKey.getFilePath(), productKey.getFileName(), productKey.getFilePassword());
        return productKey.keyUniqueIdentifier;
    }

    public Map<String, String> readAttributeMap(ProductKey productKey, Set<String> attributeMapKeySet) {
        KeyStore.Entry entry = Store.readKeyStoreEntryFromKeyStore(productKeyFileAlgorithm, productKey.getProductName(), productKey.getProductPassword(),
                productKey.getFilePath(), productKey.getFileName(), productKey.getFilePassword());
        Map<String, String> attributeMap = Store.populateAttributeMapFromSet(entry.getAttributes(), attributeMapKeySet);
        return attributeMap;
    }


    public void sign(ProductKey productKey) {
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(digitalSignatureAlgorithm, SIGNATURE_KEY_SIZE);
        Store.storeKeyPair(keyPair,
                productKey.getFilePath(), productKey.getFileName() + "_" + productKey.keyUniqueIdentifier);
    }



}
