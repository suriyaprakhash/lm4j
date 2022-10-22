package com.suriya.license.repl;

import java.util.NoSuchElementException;
import java.util.Scanner;

public class Executor {

    public static void startRepl() {
        begin();
        Scanner scanner = new Scanner(System.in);
        String command = "";
        while (!command.equals("exit")) {
            try {
                System.out.print("lm4j>");
                command = scanner.nextLine();
                String response = Handler.handleCommand(command);
                System.out.println(response);
            }
            catch (NoSuchElementException exception) {
                /* Occurs when (ctrl + c) executed*/
                exit();
                break;
            }

        }
    }

    public static void begin() {
//        System.out.println("Starting lm4j REPL ...");
    }

    public static void exit() {
//        System.out.println("exit");
    }
}
