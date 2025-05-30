package com.worldline.clients;

import static com.worldline.clients.Constants.*;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.worldline.clients.Constants.APIResponse;
import com.worldline.clients.Constants.BulkImport;

public class TokenizationClientImpl implements TokenizationClient {

    @Override
    public APIResponse createCBCKey() throws Exception {
        APIResponse apiResponse = new APIResponse();
        apiResponse.path = TOKENIZATION_CBC_KEYS_API;
        HttpResponse<byte[]> post = Client.getInstance().post(TOKENIZATION_CBC_KEYS_API, new byte[] {}, ACCEPT_ALL_HEADERS);
        apiResponse.responseBytes = post.body();
        apiResponse.response = new String(post.body());
        apiResponse.statusCode = post.statusCode();
        return apiResponse;
    }

    @Override
    public APIResponse createGCMKey() throws Exception {
        APIResponse apiResponse = new APIResponse();
        apiResponse.path = TOKENIZATION_GCM_KEYS_API;
        HttpResponse<byte[]> post = Client.getInstance().post(TOKENIZATION_GCM_KEYS_API, new byte[] {}, ACCEPT_ALL_HEADERS);
        apiResponse.responseBytes = post.body();
        apiResponse.response = new String(post.body());
        apiResponse.statusCode = post.statusCode();
        return apiResponse;
    }

    @Override
    public APIResponse tokenize(String pan, String expiry) throws Exception {
        String path = TOKEN_API.formatted(getPlatformId(), getMerchantId());

        byte[] key = KeyManager.getKey();
        byte[] iv = KeyManager.getIv();

        String body = expiry.isBlank() ? TOKENIZE_REQ_TMP_WITHOUT_EXPIRY.formatted(pan) : TOKENIZE_REQ_TMP.formatted(pan, expiry);
        byte[] bodyBytes = body.getBytes();
        byte[] encrypted = KeyManager.encrypt(bodyBytes, key, iv);

        String[] headers = buildHeadersWithIv(iv);
        HttpResponse<byte[]> resp = Client.getInstance().post(path, encrypted, headers);

        return handleResponse(path, key, resp);
    }

    @Override
    public APIResponse detokenize(String token) throws Exception {
        String path = DTOKENIZE_API.formatted(getPlatformId(), getMerchantId(), token);

        byte[] key = KeyManager.getKey();

        String[] headers = buildHeadersWithoutIv();

        HttpResponse<byte[]> resp = Client.getInstance().get(path, headers);

        return handleResponse(path, key, resp);
    }

    @Override
    public APIResponse bulkTokenize(Map<String, String> rows) throws Exception {
        String path = BULK_TOKENIZE_API.formatted(getPlatformId(), getMerchantId());

        byte[] key = KeyManager.getKey();
        byte[] iv = KeyManager.getIv();

        String bulkData = rows.keySet().stream().map(pan -> TOKENIZE_REQ_TMP.formatted(pan, rows.get(pan))).collect(Collectors.joining(","));
        byte[] bodyBytes = "[%s]".formatted(bulkData).getBytes();
        byte[] encrypted = KeyManager.encrypt(bodyBytes, key, iv);

        String[] headers = buildHeadersWithIv(iv);

        HttpResponse<byte[]> resp = Client.getInstance().post(path, encrypted, headers);

        return handleResponse(path, key, resp);
    }

    @Override
    public APIResponse bulkImport(List<BulkImport> rows) throws Exception {
        String path = BULK_IMPORT_API.formatted(getPlatformId(), getMerchantId());

        byte[] key = KeyManager.getKey();
        byte[] iv = KeyManager.getIv();

        String bulkData = rows.stream().map(r -> BULK_IMPORT_REQ_TMP.formatted(r.PAN(), r.expiry(), r.token())).collect(Collectors.joining(","));
        byte[] bodyBytes = "[%s]".formatted(bulkData).getBytes();
        byte[] encrypted = KeyManager.encrypt(bodyBytes, key, iv);

        String[] headers = buildHeadersWithIv(iv);

        HttpResponse<byte[]> resp = Client.getInstance().post(path, encrypted, headers);

        return handleResponse(path, key, resp);
    }

    @Override
    public APIResponse bulkDetokenize(List<String> tokens) throws Exception {
        String path = BULK_DETOKENIZE_API.formatted(getPlatformId(), getMerchantId());

        byte[] key = KeyManager.getKey();
        byte[] iv = KeyManager.getIv();
        String json = tokens.stream().map("\"%s\""::formatted).collect(Collectors.joining(",", "[", "]"));
        byte[] bodyBytes = json.getBytes();
        byte[] encrypted = KeyManager.encrypt(bodyBytes, key, iv);

        String[] headers = buildHeadersWithIv(iv);

        HttpResponse<byte[]> resp = Client.getInstance().post(path, encrypted, headers);

        return handleResponse(path, key, resp);
    }

    @Override
    public APIResponse deactivateToken(String token) throws Exception {
        String path = DEACTIVATE_API.formatted(getPlatformId(), getMerchantId(), token);

        String[] headers = new String[] {
                "Content-Type", "application/octet-stream",
                "ing-key-id", KeyManager.getKeyID()
        };
        HttpResponse<byte[]> resp = Client.getInstance().delete(path, headers);
        var statusCode = resp.statusCode();

        APIResponse toRet = new APIResponse();
        toRet.path = path;
        toRet.statusCode = statusCode;

        if (statusCode < 200 || statusCode >= 300) {
            toRet.response = new String(resp.body());
            toRet.responseBytes = resp.body();
            return toRet;
        }

        return toRet;
    }

    @Override
    public APIResponse getTokens(String token) throws Exception {
        String path = RETRIEVE_TOKENS_API.formatted(getPlatformId(), getMerchantId(), token);

        String[] headers = buildHeadersWithoutIv();
        HttpResponse<byte[]> resp = Client.getInstance().get(path, headers);

        var statusCode = resp.statusCode();

        APIResponse toRet = new APIResponse();
        toRet.path = path;
        toRet.statusCode = statusCode;
        toRet.response = new String(resp.body());
        Optional<String> optionalIv = resp.headers().firstValue(ING_IV_HEADER);

        if(optionalIv.isPresent()) {
            String respIv = optionalIv.get();
            toRet.responseIv = KeyManager.fromBase64(respIv);
        }
        return toRet;
    }
}