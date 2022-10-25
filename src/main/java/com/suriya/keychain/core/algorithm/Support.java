package com.suriya.keychain.core.algorithm;

import java.security.*;
import java.util.Set;
import java.util.TreeSet;

public class Support {

//    private static Generator generator;
//
//    private Generator() {
//    }
//
//    public static Generator getSingletonGenerator() {
//        if (generator == null) {
//            generator = new Generator();
//        }
//        return generator;
//    }

    public static Set<String> getSupportedAlgorithms(String crypto) {
        Set<String> algorithmSet = new TreeSet<>();
        for (Provider provider : Security.getProviders()) {
            provider.getServices().stream()
                    .filter(s -> crypto.equals(s.getType()))
                    .map(Provider.Service::getAlgorithm)
                    .forEach(algorithmSet::add);
        }
        return algorithmSet;
    }



}
