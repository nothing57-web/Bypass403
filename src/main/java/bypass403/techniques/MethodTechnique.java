package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList;
import java.util.List;

public class MethodTechnique implements BypassTechnique {
    public String getName() { return "HTTP methods & overrides"; }

    public List<HttpRequest> generateCandidates(HttpRequest original) {
        ArrayList<HttpRequest> out = new ArrayList<>();
        String[] methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS", "HEAD",
            "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"};
        for (String method : methods) out.add(original.withMethod(method));

        String[][] overrides = {
            {"X-HTTP-Method-Override", "GET"},
            {"X-HTTP-Method", "PUT"},
            {"X-Method-Override", "GET"}
        };
        for (String[] override : overrides) out.add(original.withAddedHeader(override[0], override[1]));
        return out;
    }
}
