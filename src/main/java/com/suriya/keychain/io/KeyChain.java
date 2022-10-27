package com.suriya.keychain.io;

import com.suriya.keychain.core.chain.*;
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

        BuilderStorage builderStorage = new BuilderStorage();
        builderStorage.setInfo(info);
        builderStorage.setInfoKeyAttributeMap(informationKeyAttributeMap);
        builderStorage.setHeaderMap(headerMap);

        ChainBuilder contentConnector = new ChainBuilder(builderStorage);
        keyChain.generator = new Generator(contentConnector);
        contentConnector.connect();
        return keyChain.generator;
    }

    public static class Generator {

        ChainBuilder contentConnector;

        private Generator(ChainBuilder contentConnector) {
            this.contentConnector = contentConnector;
        }

        public void deploy() {
            try {
                Path keyChainPath = Paths.get(contentConnector.getGenerationHolder().getInfo().getFilePath() + "\\" + contentConnector.getGenerationHolder().getInfo().getFileName() + ".kc");
                // write key chain
                Files.write(keyChainPath, get());
                if (saveGeneratedKeyStore) {
                    Path generatedKeyStoreFile = Paths.get(contentConnector.getGenerationHolder().getInfo().getFilePath() + "\\" + contentConnector.getGenerationHolder().getInfo().getFileName() + "_ks");
                    // write key chain
                    Files.write(generatedKeyStoreFile, getBody());
                }
                if (saveGeneratedPrivateKey) {
                    Path generatedPrivateKey = Paths.get(contentConnector.getGenerationHolder().getInfo().getFilePath() + "\\" + contentConnector.getGenerationHolder().getInfo().getFileName() + "_pk");
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
            return contentConnector.getGenerationHolder().getHeaderMap().toString().getBytes(StandardCharsets.UTF_8);
        }

        public byte[] getBody() {
            return ByteProcessor.writeKeyStoreIntoByteArray(contentConnector.getGenerationHolder().getKeyStore(), contentConnector.getGenerationHolder().getInfo().getFilePassword());
        }

        private byte[] getPrivateKey() {
            return contentConnector.getGenerationHolder().getPrivateKey().getEncoded();
        }


        private void populateDefaultHeader() {
            if (contentConnector.getGenerationHolder().getHeaderMap() == null) {
                contentConnector.getGenerationHolder().setHeaderMap(new HashMap<>());
            }
            contentConnector.getGenerationHolder().getHeaderMap().put("KEY_CHAIN_IDENTIFIER_GEN_TIME", Instant.now().toString());
        }


    }

    private static final class Verifier {

        private ChainExtractor chainExtractor;

        private Verifier(Info info, Set<String> infoKeyAttributeSet) {
            ExtractorStorage extractorStorage = new ExtractorStorage();
            extractorStorage.setInfo(info);
            extractorStorage.setInfoKeyAttributeSet(infoKeyAttributeSet);
            ChainExtractor chainExtractor = new ChainExtractor(extractorStorage);
            this.chainExtractor = chainExtractor;
        }

        private byte[] get() {
            byte[] fileByteArray = null;
            try {
             fileByteArray = Files.readAllBytes(Path.of(chainExtractor.getValidationHolder().getInfo().getFilePath() + "//" +
                     chainExtractor.getValidationHolder().getInfo().getFileName() + ".kc"));
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
            KeyStore keyStore = ByteProcessor.readKeyStoreFromByteArray(getBody(), keyStoreAlgorithm,
                    chainExtractor.getValidationHolder().getInfo().getFilePassword());
            String uuid = chainExtractor.extract(keyStore);
            boolean signatureValid = Validator.validateSignature(chainExtractor.getValidationHolder());
            return signatureValid;
        }

    }

    public static boolean verify(Info info, Set<String> infoKeyAttributeSet) {
        Verifier verifier = new Verifier(info, infoKeyAttributeSet);
        return verifier.verify();
    }


















}
