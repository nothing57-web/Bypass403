package bypass403.config;

public record Config(
    int maxPayloads,
    int threadCount,
    int delayMs,
    int requestsPerSecond,
    boolean pathEnabled,
    boolean methodEnabled,
    boolean headerEnabled,
    boolean combinationEnabled,
    boolean bodyEnabled,
    boolean fuzzEnabled,
    boolean dangerousMethodsEnabled,
    String customHeaderName,
    String customHeaderValue
) {
    public static Config defaults() {
        return new Config(200, 5, 100, 10, true, true, true, true, true, true, false, "", "");
    }

    public Config sanitized() {
        return new Config(
            clamp(maxPayloads, 1, 2000), clamp(threadCount, 1, 20), clamp(delayMs, 0, 60000),
            clamp(requestsPerSecond, 1, 1000), pathEnabled, methodEnabled, headerEnabled,
            combinationEnabled, bodyEnabled, fuzzEnabled, dangerousMethodsEnabled,
            customHeaderName == null ? "" : customHeaderName.trim(),
            customHeaderValue == null ? "" : customHeaderValue
        );
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
