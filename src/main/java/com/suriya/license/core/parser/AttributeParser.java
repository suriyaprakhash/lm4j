package com.suriya.license.core.parser;

import com.suriya.license.util.ConversionUtility;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PKCS12Attribute;
import java.util.*;
import java.util.stream.Collectors;

public class AttributeParser {

    public static String LICENSE_ID_ATTRIBUTE_NAME = "licenseId";
    public static String USER_ID_ATTRIBUTE_NAME = "userId";
    public static String HOSTNAME_ATTRIBUTE_NAME = "hostName";

    @Deprecated
    public static Set<KeyStore.Entry.Attribute> populateAttributeSetFromMap(String licenseId, String userId, String hostName) {
        Set<KeyStore.Entry.Attribute> attributeSet = new HashSet<>();
        if (licenseId != null) {
            KeyStore.Entry.Attribute licenseIdAttr = null;
            licenseIdAttr = new PKCS12Attribute(ConversionUtility.stringToASN1(LICENSE_ID_ATTRIBUTE_NAME).toString(), licenseId);
//          licenseIdAttr = new PKCS12Attribute(new ASN1ObjectIdentifier("licenseId".getBytes(StandardCharsets.UTF_8), false).getId(), userId);
            attributeSet.add(licenseIdAttr);
        }
        if (userId != null) {
            KeyStore.Entry.Attribute userIdAttr = new PKCS12Attribute(ASN1ObjectIdentifier.fromContents(USER_ID_ATTRIBUTE_NAME.getBytes(StandardCharsets.UTF_8)).toString(), userId);
            attributeSet.add(userIdAttr);
        }
        KeyStore.Entry.Attribute hostNameAttr =  new PKCS12Attribute(ASN1ObjectIdentifier.fromContents(HOSTNAME_ATTRIBUTE_NAME.getBytes(StandardCharsets.UTF_8)).toString(), hostName);
        attributeSet.add(hostNameAttr);

        return attributeSet;
    }


    public static Set<KeyStore.Entry.Attribute> populateAttributeSetFromMap(Map<String, String> attributeMap) {
        Set<KeyStore.Entry.Attribute> attributeSet =
                attributeMap.entrySet().stream().map(entry ->
                        new PKCS12Attribute(ConversionUtility.stringToASN1(entry.getKey()).toString(), entry.getValue())
                ).collect(Collectors.toSet());
        return attributeSet;
    }

    public static Map<String,String> populateAttributeMapFromSet(Set<KeyStore.Entry.Attribute> attributeSet, Set<String> attributeMapKeySet) {
        return attributeMapKeySet.stream().collect(Collectors.toMap(
                attributeKeyString -> attributeKeyString , attributeKeyString -> {
                    KeyStore.Entry.Attribute attribute = getAttributeForTheGivenKey(attributeSet, attributeKeyString);
                    if (attribute == null) {
                        return "";
                    }
                    return attribute.getValue();
                }));
    }


    private static KeyStore.Entry.Attribute getAttributeForTheGivenKey(Set<KeyStore.Entry.Attribute> attributeSet, String key) {
        Optional<KeyStore.Entry.Attribute> optionalAttribute = null;
        String oid = ConversionUtility.stringToASN1(key).toString();
        optionalAttribute = attributeSet.stream().filter(tempAttr -> tempAttr.getName().equals(oid)).findAny();
        if (optionalAttribute.isPresent()) {
            return optionalAttribute.get();
        }
        return null;
    }

    private static boolean keyOidMatchesTheAttributeOid(String oid, KeyStore.Entry.Attribute tempAttr) {
        boolean matches = false;
        try {
            if (tempAttr.getName().equals(oid)) {
                matches = true;
            }
        } catch(NoSuchElementException e) {
            e.printStackTrace();
        }
        return matches;
    }

}
