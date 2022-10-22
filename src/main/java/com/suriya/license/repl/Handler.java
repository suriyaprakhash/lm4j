package com.suriya.license.repl;

import com.suriya.license.repl.command.Command;
import com.suriya.license.repl.command.CommandIdentifier;

public class Handler {

    public static String handleCommand(String input) {
        String output = "";
        Command command = CommandIdentifier.identifyCommand(input);
        if(command.validate(input)) {
            output = command.run(input);
        } else {
            output = command.getDefaultError();
        }
        return output;
    }
}
