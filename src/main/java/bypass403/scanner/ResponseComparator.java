package bypass403.scanner;

public final class ResponseComparator {
    public boolean isBypass(ResponseSnapshot original, ResponseSnapshot candidate) {
        if (original == null || candidate == null) return false;
        if (original.status() == 403 && candidate.status() != 403 && candidate.status() > 0) return true;
        if (candidate.status() == 403) return false;
        if (candidate.status() != original.status()) return false;

        String originalNormalized = normalize(original.body());
        String candidateNormalized = normalize(candidate.body());
        return !originalNormalized.equals(candidateNormalized)
            || candidate.length() != original.length();
    }

    public String normalize(String body) {
        if (body == null) return "";
        String s = body;
        s = s.replaceAll("(?i)(timestamp|csrf|csrf[_-]?token|nonce)\"?\s*[:=]\s*\"?[^\",< }]+", "$1\"=DYNAMIC");
        s = s.replaceAll("\b[0-9]{10,13}\b", "TIMESTAMP");
        s = s.replaceAll("[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", "UUID");
        s = s.replaceAll("<input[^>]+name=[\"']?(?:csrf|nonce)[\"']?[^>]+value=[\"'][^\"']*[\"']", "<input DYNAMIC_CSRF_TOKEN");
        return s.replaceAll("\\s+", " ").trim();
    }
}
