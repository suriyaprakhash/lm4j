package com.suriya.keychain.core.chain;

public class Extractor {

    protected ExtractorStorage extractorStorage;

    public ExtractorStorage getValidationHolder() {
        return extractorStorage;
    }

    Extractor(ExtractorStorage extractorStorage) {
        this.extractorStorage = extractorStorage;
    }
}
