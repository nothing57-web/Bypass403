package bypass403.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import bypass403.test.MockHttpRequests;
import bypass403.config.Config;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

class BypassScannerTest {
    @Test
    void sendsCandidatesAndStoresResultsRespectingMaxPayloads() throws Exception {
        MontoyaApi api = org.mockito.Mockito.mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        CopyOnWriteArrayList<HttpRequest> sent = new CopyOnWriteArrayList<>();
        HttpRequestSender sender = request -> {
            sent.add(request);
            return new HttpRequestSender.SendResult(200, 42, "allowed");
        };

        BypassScanner scanner = new BypassScanner(api, request -> true, sender);
        scanner.configure(new Config(5, 2, 0, 1000, true, false, false, false, false, false, false, "", ""));
        HttpRequest original = MockHttpRequests.create("https://example.com/admin");
        scanner.scan(original, new ResponseSnapshot(403, 10, "Forbidden"));

        for (int i = 0; i < 40 && sent.size() < 5; i++) Thread.sleep(25);
        assertEquals(5, sent.size());
        assertEquals(5, scanner.getResults().size());
        assertTrue(scanner.getResults().stream().allMatch(r -> r.succeeded()));
        scanner.shutdown();
    }

    @Test
    void blocksOutOfScopeRequestsBeforeSender() throws Exception {
        MontoyaApi api = org.mockito.Mockito.mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        CopyOnWriteArrayList<HttpRequest> sent = new CopyOnWriteArrayList<>();
        BypassScanner scanner = new BypassScanner(api, request -> false, request -> {
            sent.add(request);
            return new HttpRequestSender.SendResult(200, 1, "");
        });
        scanner.scan(MockHttpRequests.create("https://blocked.example/admin"));
        Thread.sleep(100);
        assertTrue(sent.isEmpty());
        scanner.shutdown();
    }
}
