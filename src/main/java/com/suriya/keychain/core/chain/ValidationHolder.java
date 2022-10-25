package com.suriya.keychain.core.chain;


import java.security.PublicKey;

public class ValidationHolder extends Holder {
    protected PublicKey publicKey;
    protected byte[] signature;
}
