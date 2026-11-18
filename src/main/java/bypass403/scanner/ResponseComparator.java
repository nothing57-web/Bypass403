package bypass403.scanner;

public final class ResponseComparator {
    public boolean isBypass(ResponseSnapshot original, ResponseSnapshot candidate) {
        if (original == null || candidate == null) return false;

        // A bypass is a successful protected-content response, not merely a
        // status code different from 403. 400, 401, 404, 308, and similar
        // responses must remain non-bypass classifications.
        if (!isSuccessful(candidate.status())) return false;

        if (original.status() == 403) {
            String originalBody = normalize(original.body());
            String candidateBody = normalize(candidate.body());
            if (candidateBody.isBlank()) return false;
            return !originalBody.equals(candidateBody) || candidate.length() != original.length();
        }

        if (candidate.status() != original.status()) return false;
        String originalBody = normalize(original.body());
        String candidateBody = normalize(candidate.body());
        return !originalBody.equals(candidateBody)
            || candidate.length() != original.length();
    }

    public boolean isSuccessful(int status) {
        return status >= 200 && status < 300;
    }

    public String normalize(String body) {
        if (body == null) return "";
        String s = body;
        s = s.replaceAll("(?i)(timestamp|csrf|csrf[_-]?token|nonce)\"?\\s*[:=]\\s*\\\"?[^\\\",< }]+", "$1\"=DYNAMIC");
        s = s.replaceAll("\\b[0-9]{10,13}\\b", "TIMESTAMP");
        s = s.replaceAll("[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", "UUID");
        s = s.replaceAll("<input[^>]+name=[\\\"']?(?:csrf|nonce)[\\\"']?[^>]+value=[\\\"'][^\\\"']*[\\\"']", "<input DYNAMIC_CSRF_TOKEN");
        return s.replaceAll("\\s+", " ").trim();
    }
}
