package bypass403.scope;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

public interface ScopeChecker {
    boolean isInScope(HttpRequest request);

    static ScopeChecker from(MontoyaApi api) {
        return request -> request != null && api.scope().isInScope(request.url());
    }
}
