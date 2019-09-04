package com.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Arrays;

public class Main {
    private static int port = 9000;
    private static ServerSocket serverSocket;
    private static ClientHandler clientHandler;
    private static Thread thread;

    public static void main(String[] args) throws IOException {
        System.out.println("Arguments: " + Arrays.toString(args));
        if(args.length > 0) {
            port = Integer.valueOf(args[0]);
        }
        System.out.println("Starting BProt server on port " + port);


        System.out.println("Setting up shutdown hook...");
        Runtime.getRuntime().addShutdownHook(new Thread(Main::shutdown));

        System.out.println("Creating server socket...");
        serverSocket = new ServerSocket(port);
        System.out.println("Created server socket on port " + port);

        while (true) {
            clientHandler = new ClientHandler(serverSocket.accept());
            thread = new Thread(clientHandler);
            thread.start();
            System.out.println("Received request.");
        }
    }

    private static void shutdown() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
