package com.suriya.license.repl.command;

public class CommandIdentifier {

    public static Command identifyCommand(String input) {

        Command command = null;

        if (input != null && input.length() > 0) {
            command = Generate.getSingletonGenerate();
        } else {
            command = Invalid.getSingletonInvalid();
        }
        return command;
    }
}
