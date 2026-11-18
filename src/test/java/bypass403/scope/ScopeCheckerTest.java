package bypass403.scope;

import burp.api.montoya.http.message.requests.HttpRequest;
import bypass403.test.MockHttpRequests;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScopeCheckerTest {
    @Test
    void acceptsOnlyMockedInScopeRequests() {
        ScopeChecker checker = request -> request != null && request.url().startsWith("https://allowed.example/");
        assertTrue(checker.isInScope(MockHttpRequests.create("https://allowed.example/admin")));
        assertFalse(checker.isInScope(MockHttpRequests.create("https://blocked.example/admin")));
        assertFalse(checker.isInScope(null));
    }
}
