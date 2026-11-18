package bypass403.config;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ConfigManagerTest {
    @Test
    void roundTripsEverySetting() {
        Map<String, String> values = new HashMap<>();
        ConfigManager manager = new ConfigManager(new ConfigManager.ConfigStore() {
            @Override public String get(String key) { return values.get(key); }
            @Override public void set(String key, String value) { values.put(key, value); }
        });

        Config original = new Config(321, 7, 250, 22, true, false, true, false, true, false, true, "X-Test", "secret");
        manager.save(original);
        Config restored = manager.load();

        assertEquals(original.maxPayloads(), restored.maxPayloads());
        assertEquals(original.threadCount(), restored.threadCount());
        assertEquals(original.delayMs(), restored.delayMs());
        assertEquals(original.requestsPerSecond(), restored.requestsPerSecond());
        assertEquals(original.pathEnabled(), restored.pathEnabled());
        assertEquals(original.methodEnabled(), restored.methodEnabled());
        assertEquals(original.headerEnabled(), restored.headerEnabled());
        assertEquals(original.combinationEnabled(), restored.combinationEnabled());
        assertEquals(original.bodyEnabled(), restored.bodyEnabled());
        assertEquals(original.fuzzEnabled(), restored.fuzzEnabled());
        assertEquals(original.dangerousMethodsEnabled(), restored.dangerousMethodsEnabled());
        assertEquals("X-Test", restored.customHeaderName());
        assertEquals("secret", restored.customHeaderValue());
    }

    @Test
    void sanitizesInvalidNumericBounds() {
        Config sanitized = new Config(-1, 999, 999999, 0, true, true, true, true, true, true, false, null, null).sanitized();
        assertEquals(1, sanitized.maxPayloads());
        assertEquals(20, sanitized.threadCount());
        assertEquals(60000, sanitized.delayMs());
        assertEquals(1, sanitized.requestsPerSecond());
        assertEquals("", sanitized.customHeaderName());
        assertEquals("", sanitized.customHeaderValue());
    }
}
