package bypass403.scanner;

import burp.api.montoya.http.message.requests.HttpRequest;
import bypass403.test.MockHttpRequests;
import bypass403.config.Config;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BypassRequestFactoryTest {
    @Test
    void generatesKnownPathAndHeaderPayloadsWithoutDuplicates() {
        HttpRequest original = MockHttpRequests.create("https://example.com/admin");
        Config config = new Config(200, 5, 0, 100, true, false, true, true, false, true, false, "", "").sanitized();

        List<HttpRequest> candidates = new BypassRequestFactory().generate(original, config);
        Set<String> payloads = new HashSet<>();
        for (HttpRequest r : candidates) {
            StringBuilder key = new StringBuilder(r.method()).append(' ').append(r.path());
            r.headers().forEach(h -> key.append("\n").append(h.name()).append(':').append(h.value()));
            key.append("\nbody=").append(r.bodyToString());
            payloads.add(key.toString());
        }
        assertEquals(candidates.size(), payloads.size(), "candidate list must not contain duplicates");
        assertTrue(candidates.stream().anyMatch(r -> r.path().equals("/admin/")));
        assertTrue(candidates.stream().anyMatch(r -> r.path().equals("/./admin")));
        assertTrue(candidates.stream().anyMatch(r -> r.path().equals("/admin/..;/")));
        assertTrue(candidates.stream().anyMatch(r -> r.headers().stream().anyMatch(h -> h.name().equals("X-Forwarded-For") && h.value().equals("127.0.0.1"))));
        assertTrue(candidates.stream().anyMatch(r -> r.headers().stream().anyMatch(h -> h.name().equals("X-Forwarded-For") && h.value().equals("localhost"))));
    }

    @Test
    void respectsMaxPayloadsAndDangerousMethodsToggle() {
        HttpRequest original = MockHttpRequests.create("https://example.com/admin");
        Config safe = new Config(12, 5, 0, 100, true, true, true, true, true, true, false, "", "");
        List<HttpRequest> safeCandidates = new BypassRequestFactory().generate(original, safe);
        assertEquals(12, safeCandidates.size());
        assertTrue(safeCandidates.stream().noneMatch(r -> r.method().equals("TRACE") || r.method().equals("OPTIONS")));

        Config dangerous = new Config(200, 5, 0, 100, false, true, false, false, false, false, true, "", "");
        List<HttpRequest> dangerousCandidates = new BypassRequestFactory().generate(original, dangerous);
        assertTrue(dangerousCandidates.stream().anyMatch(r -> r.method().equals("TRACE")));
        assertTrue(dangerousCandidates.stream().anyMatch(r -> r.method().equals("OPTIONS")));
    }
}
