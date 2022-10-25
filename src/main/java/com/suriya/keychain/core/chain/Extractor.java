package com.suriya.keychain.core.chain;

public class Extractor {

    protected ValidationHolder validationHolder;

    public ValidationHolder getValidationHolder() {
        return validationHolder;
    }

    Extractor(ValidationHolder validationHolder) {
        this.validationHolder = validationHolder;
    }
}
