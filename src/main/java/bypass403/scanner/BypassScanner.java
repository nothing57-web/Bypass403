package bypass403.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import bypass403.config.Config;
import bypass403.model.BypassResult;
import bypass403.scope.ScopeChecker;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public final class BypassScanner {
    private final MontoyaApi api;
    private final ScopeChecker scopeChecker;
    private final HttpRequestSender sender;
    private final BypassRequestFactory factory = new BypassRequestFactory();
    private final ResponseComparator comparator = new ResponseComparator();
    private final CopyOnWriteArrayList<BypassResult> results = new CopyOnWriteArrayList<>();
    private final Set<String> scannerRequests = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean shutDown = new AtomicBoolean(false);

    private volatile ExecutorService executor;
    private volatile Config config = Config.defaults();
    private volatile Consumer<BypassResult> resultConsumer;
    private volatile Consumer<String> warningConsumer;

    public BypassScanner(MontoyaApi api) {
        this.api = api;
        this.scopeChecker = ScopeChecker.from(api);
        this.sender = HttpRequestSender.from(api);
        recreatePool();
    }

    public BypassScanner(MontoyaApi api, ScopeChecker scopeChecker, HttpRequestSender sender) {
        this.api = api;
        this.scopeChecker = scopeChecker;
        this.sender = sender;
        recreatePool();
    }

    public void setResultConsumer(Consumer<BypassResult> consumer) { this.resultConsumer = consumer; }
    public void setWarningConsumer(Consumer<String> consumer) { this.warningConsumer = consumer; }
    public List<BypassResult> getResults() { return results; }
    public void clearResults() { results.clear(); }

    public boolean isScannerRequest(HttpRequest request) {
        return request != null && scannerRequests.contains(request.toString());
    }

    public synchronized void configure(Config config) {
        this.config = config.sanitized();
        recreatePool();
    }

    private synchronized void recreatePool() {
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
        shutDown.set(false);
        executor = Executors.newFixedThreadPool(config.threadCount());
    }

    public void scan(HttpRequest original) { scan(original, null); }

    public void scan(HttpRequest original, ResponseSnapshot originalResponse) {
        if (shutDown.get()) return;
        if (original == null) { warn("Bypass403 skipped: no original request"); return; }
        if (!scopeChecker.isInScope(original)) {
            warn("Bypass403 blocked: original URL is out of scope: " + original.url());
            return;
        }

        Config snapshot = config;
        ExecutorService pool = executor;
        pool.execute(() -> {
            try {
                List<HttpRequest> candidates = factory.generate(original, snapshot);
                long spacingMs = Math.max(snapshot.delayMs(), 1000L / snapshot.requestsPerSecond());
                for (int i = 0; i < candidates.size(); i++) {
                    if (shutDown.get() || Thread.currentThread().isInterrupted()) break;
                    HttpRequest candidate = candidates.get(i);
                    if (!scopeChecker.isInScope(candidate)) {
                        warn("Bypass403 blocked: candidate URL is out of scope: " + candidate.url());
                        continue;
                    }
                    final int index = i;
                    pool.execute(() -> execute(original, originalResponse, candidate, index + 1));
                    if (i + 1 < candidates.size()) Thread.sleep(spacingMs);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                api.logging().logToError("Bypass403 scan failed: " + e);
            }
        });
    }

    private void execute(HttpRequest original, ResponseSnapshot originalResponse, HttpRequest candidate, int index) {
        if (!scopeChecker.isInScope(candidate)) {
            warn("Bypass403 blocked: candidate URL is out of scope: " + candidate.url());
            return;
        }
        String signature = candidate.toString();
        scannerRequests.add(signature);
        long start = System.nanoTime();
        try {
            HttpRequestSender.SendResult sent = sender.send(candidate);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            ResponseSnapshot candidateResponse = new ResponseSnapshot(sent.status(), sent.length(), sent.body());
            boolean bypass = originalResponse == null
                ? sent.status() != 403 && sent.status() > 0
                : comparator.isBypass(originalResponse, candidateResponse);
            BypassResult result = new BypassResult(original.url(), "Candidate #" + index, candidate,
                sent.status(), sent.length(), elapsed, bypass);
            results.add(result);
            Consumer<BypassResult> consumer = resultConsumer;
            if (consumer != null) consumer.accept(result);
        } catch (Exception e) {
            api.logging().logToError("Bypass403 candidate failed: " + e);
        } finally {
            scannerRequests.remove(signature);
        }
    }

    private void warn(String message) {
        api.logging().logToError(message);
        Consumer<String> consumer = warningConsumer;
        if (consumer != null) consumer.accept(message);
    }

    public synchronized void shutdown() {
        shutDown.set(true);
        if (executor != null) {
            executor.shutdownNow();
            try { executor.awaitTermination(2, TimeUnit.SECONDS); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        scannerRequests.clear();
    }
}
