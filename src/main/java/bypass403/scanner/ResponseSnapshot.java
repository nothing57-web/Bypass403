package bypass403.scanner;

public record ResponseSnapshot(int status, int length, String body) {}
