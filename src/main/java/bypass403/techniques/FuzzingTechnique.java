package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList;
import java.util.List;

public class FuzzingTechnique implements BypassTechnique {
    public String getName() { return "Trailing/leading fuzzing"; }

    public List<HttpRequest> generateCandidates(HttpRequest original) {
        String path = original.path();
        int queryIndex = path.indexOf('?');
        String base = queryIndex >= 0 ? path.substring(0, queryIndex) : path;
        String name = base.substring(base.lastIndexOf('/') + 1);
        String[] suffixes = {"%00", "%0d%0a", ".json", ".html", ".php", "~", "%23", "%3f", "*", "/", "/%2f" + name};

        ArrayList<HttpRequest> out = new ArrayList<>();
        for (String suffix : suffixes) out.add(original.withPath(base + suffix));
        out.add(original.withPath("/%2f" + name));
        out.add(original.withPath(base + "%2f"));
        return out;
    }
}
