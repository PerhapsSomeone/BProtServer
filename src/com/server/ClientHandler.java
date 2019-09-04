package com.server;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.Runnable;
import java.net.Socket;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;

import static java.nio.charset.StandardCharsets.UTF_8;

class ClientHandler implements Runnable {
    private Socket clientSocket;

    private PublicKey clientKey;

    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;

    private Cipher encryptionCipherServer;

    private Key clientAESKey;

    ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    public void run() {
        // create input buffer and output buffer
        // wait for input from client and send response back to client
        // close all streams and sockets

        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        keyPairGen.initialize(2048);

        KeyPair pair = keyPairGen.generateKeyPair();
        serverPublicKey = pair.getPublic();
        serverPrivateKey = pair.getPrivate();

        try {
            encryptionCipherServer = Cipher.getInstance("RSA");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }


        BufferedReader clientReader;
        try {
            clientReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        PrintStream clientOutput;
        try {
            clientOutput = new PrintStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        try {
            String data = stripString(clientReader.readLine());
            System.out.println("Received client public key: " + data);
            clientKey = PublicKeyFromString(data);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        try {
            System.out.println("Sending server public key: " + new String(Base64.getEncoder().encode(serverPublicKey.getEncoded())));
            clientOutput.println(new String(Base64.getEncoder().encode(serverPublicKey.getEncoded())));
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }


        try {
            while (clientSocket.getInputStream().available() == 0) {}
            String data = stripString(clientReader.readLine());

            clientAESKey = ClientAESKeyFromString(data);
            System.out.println("Received client AES key: " + new String(Base64.getEncoder().encode(clientAESKey.getEncoded())));

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        String url;

        try {
            while (clientSocket.getInputStream().available() == 0) {}
            String data = decryptAES(stripString(clientReader.readLine()), clientAESKey);
            url = data;
            System.out.println("Read user input (decrypted): " + data);

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        try {
            String encryptedData = encryptAES(DataHandler.getData(url), clientAESKey);
            clientOutput.println(encryptedData);
            System.out.println("Sending encrypted response to client: " + encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        System.out.println("Closing session...");
    }

    private String stripString(String orig) {
        return orig.replace("\n", "").replace("\r", "");
    }

    private PublicKey PublicKeyFromString(String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private Key ClientAESKeyFromString(String key) throws Exception {
        key = decrypt(key);
        byte[] keyBytes = Base64.getDecoder().decode(key);

        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    private String encryptServerMsg(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public String decrypt(String cipherText) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    private String decryptAES(String ciphertext, Key aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = aesKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);

        // Entschluesseln
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] clearBytes = cipher.doFinal(cipherBytes);

        return new String(clearBytes);
    }

    private String encryptAES(String cleartext, Key aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = aesKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(cleartext.getBytes());


        return new String(Base64.getEncoder().encode(encrypted));
    }
}