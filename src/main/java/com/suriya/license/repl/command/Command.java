package com.suriya.license.repl.command;

public interface Command {

    public boolean validate(String command);

    public String run(String command);

    public String getDefaultError();
}
