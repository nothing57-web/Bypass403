package bypass403.config;

import burp.api.montoya.MontoyaApi;

public final class ConfigManager {
    private static final String KEY = "bypass403.config.v2";

    public interface ConfigStore {
        String get(String key);
        void set(String key, String value);
    }

    private final ConfigStore store;

    public ConfigManager(MontoyaApi api) {
        this.store = new ConfigStore() {
            @Override public String get(String key) { return api.persistence().extensionData().getString(key); }
            @Override public void set(String key, String value) { api.persistence().extensionData().setString(key, value); }
        };
    }

    public ConfigManager(ConfigStore store) { this.store = store; }

    public Config load() {
        String value = store.get(KEY);
        if (value == null) return Config.defaults();
        try {
            String[] a = value.split("\\|", -1);
            if (a.length != 14) return Config.defaults();
            return new Config(
                Integer.parseInt(a[1]), Integer.parseInt(a[2]), Integer.parseInt(a[3]), Integer.parseInt(a[4]),
                Boolean.parseBoolean(a[5]), Boolean.parseBoolean(a[6]), Boolean.parseBoolean(a[7]),
                Boolean.parseBoolean(a[8]), Boolean.parseBoolean(a[9]), Boolean.parseBoolean(a[10]),
                Boolean.parseBoolean(a[11]), a[12], a[13]
            ).sanitized();
        } catch (RuntimeException e) {
            return Config.defaults();
        }
    }

    public void save(Config config) {
        Config c = config.sanitized();
        String value = String.join("|", "v2", Integer.toString(c.maxPayloads()), Integer.toString(c.threadCount()),
            Integer.toString(c.delayMs()), Integer.toString(c.requestsPerSecond()), Boolean.toString(c.pathEnabled()),
            Boolean.toString(c.methodEnabled()), Boolean.toString(c.headerEnabled()), Boolean.toString(c.combinationEnabled()),
            Boolean.toString(c.bodyEnabled()), Boolean.toString(c.fuzzEnabled()), Boolean.toString(c.dangerousMethodsEnabled()),
            c.customHeaderName().replace("|", ""), c.customHeaderValue().replace("|", ""));
        store.set(KEY, value);
    }
}
