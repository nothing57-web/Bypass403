package bypass403.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

public interface HttpRequestSender {
    SendResult send(HttpRequest request) throws Exception;

    record SendResult(int status, int length, String body) {}

    static HttpRequestSender from(MontoyaApi api) {
        return request -> {
            var response = api.http().sendRequest(request);
            if (!response.hasResponse()) return new SendResult(0, 0, "");
            var httpResponse = response.response();
            return new SendResult(httpResponse.statusCode(), httpResponse.body().length(), httpResponse.bodyToString());
        };
    }
}
