package com.worldline.clients;

import java.util.Properties;

public class Config {

    private static Properties config;
    
    protected synchronized static Properties getConfig() {
        if (config == null) {
            config = new Properties();
            try (var stream = Config.class.getClassLoader().getResourceAsStream("tokenization.properties")) {
                if (stream == null) {
                    throw new RuntimeException("Config file 'tokenization.properties' not found in classpath.");
                }
                config.load(stream);
            } catch (Exception e) {
                throw new RuntimeException("Error loading config file", e);
            }
        }
        return config;
    }
    
    protected static String getProfileConfigValue(String prop) {
        String profile = getConfig().getProperty("current.profile");
        return getConfig().getProperty(profile + "." + prop);
    }
}
