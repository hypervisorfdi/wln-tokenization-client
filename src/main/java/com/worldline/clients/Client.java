package com.worldline.clients;

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Duration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class Client {
    private final SSLContext sslContext;
    private final String BASE_URL;
    private static Client instance;

    public static Client getInstance() throws Exception {
        if (instance == null) {
            synchronized (Client.class) {
                if (instance == null) {
                    instance = new Client();
                }
            }
        }
        return instance;
    }

    private Client() throws Exception {
        BASE_URL = Config.getConfig().getProperty("base.url");
        String keystorepath = Config.getProfileConfigValue("keystore.path");
        String keystorepass = Config.getProfileConfigValue("keystore.pass");

        if (!Paths.get(keystorepath).toFile().exists()) {
            throw new IllegalArgumentException("Keystore file not found: " + keystorepath);
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream keyStoreStream = new FileInputStream(keystorepath)) {
            keyStore.load(keyStoreStream, keystorepass.toCharArray());
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keystorepass.toCharArray());
        
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
    }
    
    public HttpResponse<byte[]> get(String path, String... headers) throws Exception {
        HttpClient client = getClient();
        
        URI uri = URI.create(BASE_URL + path);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .headers(headers)
                .GET()
                .build();
        
        return client.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }
    
    public HttpResponse<byte[]> post(String path, byte[] body, String... headers) throws Exception {
        HttpClient client = getClient();

        URI uri = URI.create(BASE_URL + path);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .headers(headers)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        
        return client.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }
    
    public HttpResponse<byte[]> delete(String path, String... headers) throws Exception {
        HttpClient client = getClient();

        URI uri = URI.create(BASE_URL + path);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .headers(headers)
                .DELETE()
                .build();
        
        return client.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private HttpClient getClient() throws Exception {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(15))
                .sslContext(sslContext)
                .build();
    }
}
