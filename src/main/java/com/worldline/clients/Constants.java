package com.worldline.clients;


import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Constants {
    protected static final ObjectMapper mapper = new ObjectMapper();
    protected static final String TOKENIZATION_CBC_KEYS_API = "/keyservice/keys";
    protected static final String TOKENIZATION_GCM_KEYS_API = "/tokenserver/keys";
    protected static final String TOKENIZATION_BASE = "/tokenserver/merchants/%s/%s";
    protected static final String TOKEN_API = TOKENIZATION_BASE + "/tokens";
    protected static final String DTOKENIZE_API = TOKEN_API + "/%s/paymentcredentials";
    protected static final String DEACTIVATE_API = TOKEN_API + "/%s";
    protected static final String RETRIEVE_TOKENS_API = TOKEN_API + "/%s";
    protected static final String BULK_TOKENIZE_API = TOKENIZATION_BASE + "/bulk/tokenize";
    protected static final String BULK_IMPORT_API = TOKENIZATION_BASE + "/bulk/import";
    protected static final String BULK_DETOKENIZE_API = TOKENIZATION_BASE + "/bulk/detokenize";

    protected static final String ING_IV_HEADER = "ing-iv";
    protected static final String[] ACCEPT_ALL_HEADERS = new String[] {
            "Accept", "*/*",
    };
    
    protected static final String TOKENIZE_REQ_TMP = """
            {
                "paymentMethod": "CARD",
                "paymentCredentials": "%s",
                "expiryDate": "%s",
                "verifiedPayment": true
            }
            """;
    protected static final String TOKENIZE_REQ_TMP_WITHOUT_EXPIRY = """
            {
                "paymentMethod": "CARD",
                "paymentCredentials": "%s"
            }
            """;
    protected static final String BULK_IMPORT_REQ_TMP = """
            {
                "paymentMethod": "CARD",
                "paymentCredentials": "%s",
                "expiryDate": "%s",
                "verifiedPayment": true,
                "tokens": [{ "tokenType": "GENERATED", "token": "%s" }]
            }
            """;
    
    public static class APIResponse {
        public int statusCode;
        public String response;
        public byte[] responseBytes;
        public byte[] responseIv;
        public String path;
        
        public static String getFirstToken(String response) throws Exception {
            JsonNode jsonNode = mapper.readTree(response);
            return jsonNode.get("tokens").get(0).get("token").asText();
        }
        
        public String getFirstToken() throws Exception {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(200));
            JsonNode jsonNode = mapper.readTree(response);
            return jsonNode.get("tokens").get(0).get("token").asText();
        }
    }
    
    protected static APIResponse handleResponse(String path, byte[] key, HttpResponse<byte[]> resp) {
        var statusCode = resp.statusCode();
        
        APIResponse toRet = new APIResponse();
        toRet.path = path;
        toRet.statusCode = statusCode;
        
        Optional<String> optionalIv = resp.headers().firstValue(ING_IV_HEADER);
        if (statusCode < 200 || statusCode >= 300) {
            toRet.response = new String(resp.body());
            if(optionalIv.isPresent()) {
                String respIv = optionalIv.get();
                toRet.responseIv = KeyManager.fromBase64(respIv);
            }
            toRet.responseBytes = resp.body();
            return toRet;
        }
        
        byte[] encryptedResp = resp.body();
        String respIv = optionalIv.orElseThrow();
        byte[] responseIv = KeyManager.fromBase64(respIv);
        
        byte[] decrypted = KeyManager.decrypt(encryptedResp, key, responseIv);
        toRet.response = new String(decrypted);
        toRet.responseBytes = encryptedResp;
        toRet.responseIv = responseIv;
        return toRet;
    }
    
    public record BulkImport(String PAN, String expiry, String token){
        
    }
    
    protected static String[] buildHeadersWithIv(byte[] iv) {
        return new String[] {
            ING_IV_HEADER, KeyManager.toBase64(iv),
            "Content-Type", "application/octet-stream",
            ING_IV_HEADER, KeyManager.toBase64(iv),
            "ing-key-id", KeyManager.getKeyID()
        };
    }

    protected static String[] buildHeadersWithoutIv() {
        return new String[] {
            "Content-Type", "application/octet-stream",
            "ing-key-id", KeyManager.getKeyID()
        };
    }
    
    protected static String getMerchantId() {
        return Config.getProfileConfigValue("platform.merchant.id");
    }

    protected static String getPlatformId() {
        return Config.getProfileConfigValue("platform.id");
    }
    
}
