package bypass403.test;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import bypass403.test.MockHttpRequests;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class MockHttpRequests {
    private MockHttpRequests() {}

    public static HttpRequest create(String url) {
        String path = url.contains("/") ? url.substring(url.indexOf('/', url.indexOf("//") + 2)) : "/";
        return create(url, "GET", path, new ArrayList<>());
    }

    private static HttpRequest create(String url, String method, String path, List<HttpHeader> headers) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        when(request.path()).thenReturn(path);
        when(request.pathWithoutQuery()).thenReturn(path.contains("?") ? path.substring(0, path.indexOf('?')) : path);
        when(request.method()).thenReturn(method);
        when(request.toString()).thenReturn(method + " " + url + path);
        when(request.headers()).thenReturn(headers);
        when(request.bodyToString()).thenReturn("");

        when(request.withPath(anyString())).thenAnswer(invocation -> {
            String newPath = invocation.getArgument(0);
            return create(url, method, newPath, new ArrayList<>(headers));
        });
        when(request.withMethod(anyString())).thenAnswer(invocation ->
            create(url, invocation.getArgument(0), path, new ArrayList<>(headers)));
        when(request.withAddedHeader(anyString(), anyString())).thenAnswer(invocation -> {
            List<HttpHeader> copy = new ArrayList<>(headers);
            copy.add(header(invocation.getArgument(0), invocation.getArgument(1)));
            return create(url, method, path, copy);
        });
        when(request.withHeader(anyString(), anyString())).thenAnswer(invocation -> {
            List<HttpHeader> copy = new ArrayList<>(headers);
            copy.add(header(invocation.getArgument(0), invocation.getArgument(1)));
            return create(url, method, path, copy);
        });
        when(request.withBody(anyString())).thenAnswer(invocation -> {
            HttpRequest copy = create(url, method, path, new ArrayList<>(headers));
            when(copy.bodyToString()).thenReturn(invocation.getArgument(0));
            return copy;
        });
        return request;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }
}
