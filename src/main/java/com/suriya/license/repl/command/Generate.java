package com.suriya.license.repl.command;

public class Generate implements Command{

    private static Generate generate;

    private Generate() {}

    public static Generate getSingletonGenerate() {
        if (generate == null) {
            generate = new Generate();
        }
        return generate;
    }

    @Override
    public boolean validate(String command) {
        return true;
    }

    @Override
    public String run(String command) {
        return "generate run success";
    }

    @Override
    public String getDefaultError() {
        return "generate command missing args";
    }
}
