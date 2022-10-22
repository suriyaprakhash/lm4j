package com.suriya.license.repl.command;

public class Invalid implements Command{

    private static Invalid invalid;

    private Invalid() {}

    public static Invalid getSingletonInvalid() {
        if (invalid == null) {
            invalid = new Invalid();
        }
        return invalid;
    }

    @Override
    public boolean validate(String command) {
        return true;
    }

    @Override
    public String run(String command) {
        return "Invalid command";
    }

    @Override
    public String getDefaultError() {
        return "Invalid command - not applicable";
    }
}
