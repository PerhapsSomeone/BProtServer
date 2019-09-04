package com.server;

public class DataHandler {
    public static String getData(String url) {
        if(url.equals("") || url.equals("/")) {
            return "<h1>TestMessage.</h1><br />";
        } else if(url.equals("/1")) {
            return "<h1>Seite 1! Hallo! :)</h1>";
        } else {
            return "Not found.";
        }
    }
}
