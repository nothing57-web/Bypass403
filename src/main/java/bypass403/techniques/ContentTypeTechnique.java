package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList; import java.util.List;

public class ContentTypeTechnique implements BypassTechnique {
    public String getName(){ return "Body manipulation"; }
    public List<HttpRequest> generateCandidates(HttpRequest original){
        ArrayList<HttpRequest> out=new ArrayList<>();
        out.add(original.withMethod("POST").withBody(""));
        out.add(original.withMethod("POST").withHeader("Content-Type","application/json").withBody("{\"role\":\"admin\"}"));
        out.add(original.withMethod("POST").withHeader("Content-Type","application/x-www-form-urlencoded").withBody("role=admin"));
        return out;
    }
}
