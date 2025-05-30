package com.worldline.clients;

import java.util.List;
import java.util.Map;

import com.worldline.clients.Constants.APIResponse;
import com.worldline.clients.Constants.BulkImport;

public interface TokenizationClient {
    APIResponse createCBCKey() throws Exception;
    APIResponse createGCMKey() throws Exception;
    APIResponse tokenize(String pan, String expiry) throws Exception;
    APIResponse detokenize(String token) throws Exception;
    APIResponse bulkTokenize(Map<String, String> rows) throws Exception;
    APIResponse bulkImport(List<BulkImport> rows) throws Exception;
    APIResponse bulkDetokenize(List<String> tokens) throws Exception;
    APIResponse deactivateToken(String token) throws Exception;
    APIResponse getTokens(String token) throws Exception;
}

