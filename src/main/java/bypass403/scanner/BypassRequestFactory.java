package bypass403.scanner;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import bypass403.config.Config;
import bypass403.techniques.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class BypassRequestFactory {
    public List<HttpRequest> generate(HttpRequest original, Config config) {
        List<HttpRequest> candidates = new ArrayList<>();
        if (original == null) return candidates;

        if (config.pathEnabled()) add(candidates, new PathManipulationTechnique().generateCandidates(original));
        if (config.methodEnabled()) add(candidates, new MethodTechnique().generateCandidates(original));
        if (config.headerEnabled()) add(candidates, new HeaderInjectionTechnique().generateCandidates(original));
        if (config.combinationEnabled()) add(candidates, new PathHeaderCombinationTechnique().generateCandidates(original));
        if (config.bodyEnabled()) add(candidates, new ContentTypeTechnique().generateCandidates(original));
        if (config.fuzzEnabled()) add(candidates, new FuzzingTechnique().generateCandidates(original));

        if (!config.dangerousMethodsEnabled()) {
            candidates.removeIf(r -> "OPTIONS".equalsIgnoreCase(r.method()) || "TRACE".equalsIgnoreCase(r.method()));
        }

        if (!config.customHeaderName().isEmpty()) {
            candidates.replaceAll(r -> r.withAddedHeader(config.customHeaderName(), config.customHeaderValue()));
        }

        Map<String, HttpRequest> unique = new LinkedHashMap<>();
        for (HttpRequest candidate : candidates) {
            StringBuilder key = new StringBuilder(candidate.method()).append(' ').append(candidate.path());
            for (HttpHeader header : candidate.headers()) {
                key.append('\n').append(header.name()).append(':').append(header.value());
            }
            key.append("\nbody=").append(candidate.bodyToString());
            unique.putIfAbsent(key.toString(), candidate);
        }
        List<HttpRequest> result = new ArrayList<>(unique.values());
        return result.subList(0, Math.min(config.maxPayloads(), result.size()));
    }

    private void add(List<HttpRequest> target, List<HttpRequest> candidates) {
        if (candidates != null) target.addAll(candidates);
    }
}
