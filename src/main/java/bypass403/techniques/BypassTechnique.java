package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;

public interface BypassTechnique {
    String getName();
    List<HttpRequest> generateCandidates(HttpRequest original) throws Exception;
}
