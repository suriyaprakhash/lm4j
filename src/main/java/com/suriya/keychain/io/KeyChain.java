package com.suriya.keychain.io;

import com.suriya.keychain.core.ChainValidator;
import com.suriya.keychain.core.algorithm.AsymmetricKey;
import com.suriya.keychain.core.algorithm.DigiSign;
import com.suriya.keychain.core.algorithm.Hash;
import com.suriya.keychain.core.algorithm.SymmetricKey;
import com.suriya.keychain.core.parser.AttributeParser;
import com.suriya.keychain.core.parser.ByteProcessor;
import com.suriya.keychain.core.parser.Content;
import com.suriya.license.io.Info;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.time.Instant;
import java.util.*;

import static com.suriya.keychain.io.Settings.General.*;
import static com.suriya.keychain.io.Settings.Algorithm.*;

public final class KeyChain {

    private Generator generator;
    private Verifier verifier;

    private KeyChain() {}

    private static void validateInput(Info info, Map<String, String> infoKeyAttributeMap) {
    }

    public static Generator generate(Info info, Map<String, String> infoKeyAttributeMap) {
        return generate(info, infoKeyAttributeMap, null);
    }

    public static Generator generate(Info info, Map<String, String> informationKeyAttributeMap, Map<String, String> headerMap) {
        validateInput(info, informationKeyAttributeMap);
        KeyChain keyChain = new KeyChain();
        keyChain.generator = new Generator();
        keyChain.generator.info = info;
        keyChain.generator.infoKeyAttributeMap = informationKeyAttributeMap;
        keyChain.generator.headerMap = headerMap;
        keyChain.generator.bindSignatureKey(keyChain.generator.bindPublicKey(keyChain.generator.bindProductKey()));
        return keyChain.generator;
    }

    public static class Generator {
        private Info info;
        private Map<String, String> infoKeyAttributeMap;
        private Map<String, String> headerMap;

        private KeyStore keyStore;
        private PublicKey publicKey;
        private PrivateKey privateKey;
        private byte[] signature;

        private Generator() {}

        public void deploy() {
            try {
                Path keyChainPath = Paths.get(info.getFilePath() + "\\" + info.getFileName() + ".kc");
                // write key chain
                Files.write(keyChainPath, get());
                if (saveGeneratedKeyStore) {
                    Path generatedKeyStoreFile = Paths.get(info.getFilePath() + "\\" + info.getFileName() + "_ks");
                    // write key chain
                    Files.write(generatedKeyStoreFile, getBody());
                }
                if (saveGeneratedPrivateKey) {
                    Path generatedPrivateKey = Paths.get(info.getFilePath() + "\\" + info.getFileName() + "_pk");
                    // write key chain
                    Files.write(generatedPrivateKey, getPrivateKey());
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public byte[] get() {
           return Content.encode(getHeader(), getBody());
        }

        public byte[] getHeader() {
            populateDefaultHeader();
            return headerMap.toString().getBytes(StandardCharsets.UTF_8);
        }

        public byte[] getBody() {
            return ByteProcessor.writeKeyStoreIntoByteArray(keyStore, info.getFilePassword());
        }

        private byte[] getPrivateKey() {
            return privateKey.getEncoded();
        }


        private void populateDefaultHeader() {
            if (headerMap == null) {
                headerMap = new HashMap<>();
            }
            headerMap.put("KEY_CHAIN_IDENTIFIER_GEN_TIME", Instant.now().toString());
        }

        private String bindProductKey() {
            Key secretProductKey = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm); //DES HmacSHA1
            String encodedProductKeyString = Base64.getEncoder().encodeToString(secretProductKey.getEncoded());
            keyStore = ByteProcessor.keyStoreFromKeyStoreByteArray(null, keyStoreAlgorithm,
                    info.getFilePassword());
            ByteProcessor.storeSecretKeyInKeyStore(keyStore, keyStoreAlgorithm, info.getFilePassword(), secretProductKey,
                    INFO_KEY, info.getProductPassword(),
                    AttributeParser.populateAttributeSetFromMap(infoKeyAttributeMap));
            return encodedProductKeyString;
        }

        private String bindPublicKey(String encodedProductKeyString) {
            Key secretPublicKey = SymmetricKey.generateSecureRandomKey(secureRandomKeyAlgorithm);
            String encodedPublicKeyString = Base64.getEncoder().encodeToString(secretPublicKey.getEncoded());
            KeyPair keyPair = AsymmetricKey.generateAsymmetricKey(keyPairAlgorithm, keyPairKeySize);
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            Map<String, String> publicKeyAttributeMap = new HashMap<>();
            publicKeyAttributeMap.put(PUBLIC_KEY, Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            ByteProcessor.storeSecretKeyInKeyStore(keyStore, keyStoreAlgorithm, info.getFilePassword(),
                    secretPublicKey, PUBLIC_KEY, encodedProductKeyString, AttributeParser.populateAttributeSetFromMap(publicKeyAttributeMap));
            return encodedPublicKeyString;
        }

        private void bindSignatureKey(String encodedPublicKeyString) {
            String infoKeyUniqueIdentifier = Hash.getHexStringFromByteArray(Hash.generateMessageDigest(messageDigestAlgorithm,
                    infoKeyAttributeMap.toString()));
            Key secretSignatureKey = SymmetricKey.generateSecretKeyFromPassword(passwordKeyAlgorithm, infoKeyUniqueIdentifier);
            signature = DigiSign.sign(signAlgorithm, privateKey, (Base64.getEncoder().encodeToString(publicKey.getEncoded())
                    + infoKeyUniqueIdentifier).getBytes(StandardCharsets.UTF_8));
            Map<String, String> signatureAttributeMap = new HashMap<>();
            signatureAttributeMap.put("signature", Base64.getEncoder().encodeToString(signature));

            ByteProcessor.storeSecretKeyInKeyStore(keyStore, keyStoreAlgorithm, info.getFilePassword(), secretSignatureKey,  SIGNATURE_KEY, encodedPublicKeyString, AttributeParser.populateAttributeSetFromMap(signatureAttributeMap));
        }
    }

    private static final class Verifier {

        private ChainValidator chainValidator;

        private Verifier(Info info, Set<String> infoKeyAttributeSet) {
            ChainValidator chainValidator = new ChainValidator();
            chainValidator.setInfo(info);
            chainValidator.setInfoKeyAttributeSet(infoKeyAttributeSet);
            this.chainValidator = chainValidator;
        }

        private byte[] get() {
            byte[] fileByteArray = null;
            try {
             fileByteArray = Files.readAllBytes(Path.of(chainValidator.getInfo().getFilePath() + "//" + chainValidator
                     .getInfo().getFileName() + ".kc"));
            } catch (IOException e) {
                e.printStackTrace();
            }
            return fileByteArray;
        }

        private byte[] getHeader() {
            return Content.decode(get(), Content.Type.HEADER);
        }

        private byte[] getBody() {
            return Content.decode(get(), Content.Type.BODY);
        }

        private boolean verify() {
            // READ
            KeyStore keyStore = ByteProcessor.readKeyStoreFromByteArray(getBody(), keyStoreAlgorithm, chainValidator
                    .getInfo().getFilePassword());
            String uuid = chainValidator.validate(keyStore);
            return false;
        }



    }

    public static boolean verify(Info info, Set<String> infoKeyAttributeSet) {
        Verifier verifier = new Verifier(info, infoKeyAttributeSet);
        return verifier.verify();
    }


















}
