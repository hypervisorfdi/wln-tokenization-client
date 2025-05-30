package com.worldline.clients;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {
    private static final int GCM_TAG_LENGTH = 16; // 128 bits in bytes
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    
    public static String getKeyID() {
        return Config.getProfileConfigValue("key.id");
    }
    
    public static byte[] getKey() {
        String keyHex = Config.getProfileConfigValue("key.hex");
        return HexFormat.of().parseHex(keyHex);
    }
    
    public static byte[] decrypt(byte[] bodyBytes, byte[] key, byte[] iv) {
        try {
            boolean isGCM = getKeyID().length() == 4;
            return isGCM ? decryptGCM(bodyBytes, key, iv) : decryptCBC(bodyBytes, key, iv);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed. Ensure the key, IV, and data are correct.", e);
        }
    }
    
    public static byte[] encrypt(byte[] responseBody, byte[] key, byte[] iv) {
        try {
            boolean isGCM = getKeyID().length() == 4;
            return isGCM ? encryptGCM(responseBody, key, iv) : encryptCBC(responseBody, key, iv);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed. Ensure the key, IV, and data are correct.", e);
        }
    }
    
    public static byte[] decryptCBC(byte[] bodyBytes, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decryptedBodyBytes = cipher.doFinal(bodyBytes);
        
        int paddingLength = decryptedBodyBytes[decryptedBodyBytes.length - 1];
        return Arrays.copyOf(decryptedBodyBytes, decryptedBodyBytes.length - paddingLength);

    }
    
    public static byte[] encryptCBC(byte[] responseBody, byte[] key, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(responseBody);
    }
    
    public static byte[] decryptGCM(byte[] bodyBytes, byte[] keyBytes, byte[] iv) throws Exception {
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(bodyBytes);
    }

    public static byte[] encryptGCM(byte[] responseBody, byte[] keyBytes, byte[] iv) throws Exception {
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(responseBody);
    }
    
    public static byte[] getIv() {
        boolean isGCM = getKeyID().length() == 4;
        SecureRandom secureRandom = new SecureRandom();
        byte[] rnd = new byte[isGCM ? 12: 16];
        secureRandom.nextBytes(rnd);
        return rnd;
    }
    
    public static String toBase64(byte[] iv) {
        return Base64.getEncoder().encodeToString(iv);
    }

    public static byte[] fromBase64(String iv) {
        return Base64.getDecoder().decode(iv);
    }
}
