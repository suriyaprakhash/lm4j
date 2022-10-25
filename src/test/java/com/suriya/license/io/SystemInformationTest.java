package com.suriya.license.io;

import org.junit.jupiter.api.Test;

import java.io.IOException;

public class SystemInformationTest {

    @Test
    public void testSystemInformation() throws IOException {
        System.out.println(SystemInformation.OS.getSystemInfo());
    }
}
