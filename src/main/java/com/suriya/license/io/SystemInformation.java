package com.suriya.license.io;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class SystemInformation {

    private SystemInformation() {
    }

    public static class OS {

        private static String systemInfo;

        static String getSystemInfo() throws IOException {
            if (systemInfo == null) {
                String operSys = System.getProperty("os.name").toLowerCase();
                if (operSys.contains("win")) {
                    systemInfo = Windows.get();
                } else if (operSys.contains("nix") || operSys.contains("nux")
                        || operSys.contains("aix")) {
//                    systemInfo = Linux.get();
                } else if (operSys.contains("mac")) {
//                    systemInfo = Mac.get();
                } else if (operSys.contains("sunos")) {
//                    systemInfo = Solaris.get();
                }
            }
            return systemInfo;
        }
    }

    public static class Windows extends OS
    {
        static String get() throws IOException
        {
            Runtime runtime = Runtime.getRuntime();
            Process process = runtime.exec("systeminfo");
            BufferedReader systemInformationReader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            StringBuilder stringBuilder = new StringBuilder();
            String line;

            while ((line = systemInformationReader.readLine()) != null)
            {
                stringBuilder.append(line);
                stringBuilder.append(System.lineSeparator());
            }

            return stringBuilder.toString().trim();
        }
    }
}
