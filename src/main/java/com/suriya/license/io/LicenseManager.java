package com.suriya.license.io;

import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.FileProcessor;
import com.suriya.keychain.core.algorithm.AsymmetricKey;
import com.suriya.keychain.core.algorithm.SymmetricKey;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Map;
import java.util.Set;

@Deprecated
public final class LicenseManager extends BaseLicenseManager {

    private static LicenseManager licenseManager;

    private LicenseManager() {}

    public static LicenseManager getInstance() {
        if (licenseManager == null) {
            licenseManager = new LicenseManager();
        }
        return licenseManager;
    }


    private void validateInput(Info info) {

    }


    private void massageInput(Info info) {
        // if key password missing, file password is used for key
        if (info.getProductPassword() == null) {
            info.setProductPassword(info.getFilePassword());
        }
    }

    public String generate(Info info, Map<String, String> attributeMap) {

        validateInput(info);

        massageInput(info);

        // ProductKeyFile generation
        Key secureProductKey = SymmetricKey.generateSecureRandomKey(productKeyAlgorithm);
        FileProcessor.storeSecretKeyInKeyStore(productKeyFileAlgorithm, secureProductKey, AttributeParser.populateAttributeSetFromMap(attributeMap),
                info.getProductName(), info.getProductPassword(),
                info.getFilePath(), info.getFileName(), info.getFilePassword());
        return info.keyUniqueIdentifier;
    }

    public Map<String, String> readAttributeMap(Info info, Set<String> attributeMapKeySet) {
        KeyStore.Entry entry = FileProcessor.readKeyStoreEntryFromKeyStore(productKeyFileAlgorithm, info.getProductName(), info.getProductPassword(),
                info.getFilePath(), info.getFileName(), info.getFilePassword());
        Map<String, String> attributeMap = AttributeParser.populateAttributeMapFromSet(entry.getAttributes(), attributeMapKeySet);
        return attributeMap;
    }


    public void sign(Info info) {
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(digitalSignatureAlgorithm, SIGNATURE_KEY_SIZE);
        FileProcessor.storeKeyPair(keyPair,
                info.getFilePath(), info.getFileName() + "_" + info.keyUniqueIdentifier);
    }



}
