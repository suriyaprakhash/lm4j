package com.suriya.keychain.core.chain;

public class Builder {

    protected BuilderStorage builderStorage;

    public BuilderStorage getGenerationHolder() {
        return builderStorage;
    }

    Builder(BuilderStorage builderStorage) {
        this.builderStorage = builderStorage;
    }
}
