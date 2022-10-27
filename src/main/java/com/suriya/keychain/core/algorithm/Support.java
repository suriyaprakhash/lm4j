package com.suriya.keychain.core.algorithm;

import java.security.*;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

public class Support {

    /**
     * Returns the supported algorithm based on the generator
     * @param cryptoGenerator
     * @return
     */
    public static Set<String> getSupportedAlgorithms(String cryptoGenerator) {
        Set<String> algorithmSet = new TreeSet<>();
        Arrays.stream(Security.getProviders()).forEach(provider -> {
            provider.getServices().stream()
                    .filter(s -> cryptoGenerator.equals(s.getType()))
                    .map(Provider.Service::getAlgorithm)
                    .forEach(algorithmSet::add);
        });
        return algorithmSet;
    }



}
