package bypass403.model;

import burp.api.montoya.http.message.requests.HttpRequest;

public record BypassResult(
    String originalUrl,
    String technique,
    HttpRequest request,
    int status,
    int length,
    long timeMs,
    boolean bypass
) {
    public boolean succeeded() { return bypass; }
}
