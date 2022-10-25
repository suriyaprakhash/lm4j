package com.suriya.keychain.core.parser;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class ContentTest {

    @Test
    public void encodeDecodeTest() {

        String header = "head";
        String body = "body is somehat long";
        byte[] computed = Content.encode(header.getBytes(StandardCharsets.UTF_8), body.getBytes(StandardCharsets.UTF_8));

        byte[] headerRead = Content.decode(computed, Content.Type.HEADER);
        byte[] bodyRead = Content.decode(computed, Content.Type.BODY);
        System.out.println(header + " - " + new String(headerRead));
        Assertions.assertTrue(header.equals(new String(headerRead)));
        System.out.println(body + " - " + new String(bodyRead));
        Assertions.assertTrue(body.equals(new String(bodyRead)));
    }

}
