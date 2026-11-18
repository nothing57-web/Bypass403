package bypass403.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import bypass403.scanner.BypassScanner;
import bypass403.scanner.ResponseSnapshot;

public class BypassHttpHandler implements HttpHandler {
    private final BypassScanner scanner;

    public BypassHttpHandler(MontoyaApi api, BypassScanner scanner) {
        this.scanner = scanner;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (response.statusCode() == 403
            && !scanner.isScannerRequest(response.initiatingRequest())) {
            scanner.scan(response.initiatingRequest(), new ResponseSnapshot(
                response.statusCode(), response.body().length(), response.bodyToString()));
        }
        return ResponseReceivedAction.continueWith(response);
    }
}
