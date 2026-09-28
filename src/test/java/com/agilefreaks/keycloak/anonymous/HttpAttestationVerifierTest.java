package com.agilefreaks.keycloak.anonymous;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Against a real local HTTP server, since what matters is how each kind of answer is read. */
class HttpAttestationVerifierTest {

    private HttpServer server;
    private final AtomicReference<String> received = new AtomicReference<>();
    private volatile int status = 200;
    private volatile String body = "{\"success\": true}";

    private final HttpAttestationVerifier verifier = new HttpAttestationVerifier();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/verify", exchange -> {
            received.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/verify";
    }

    @Test
    void theTokenIsPostedAsAFormField() {
        verifier.accepts(url(), "a b&c");

        assertThat(received.get()).isEqualTo("token=a+b%26c");
    }

    @Test
    void successTrueAccepts() {
        assertThat(verifier.accepts(url(), "t")).isTrue();
    }

    @Test
    void successFalseRejects() {
        body = "{\"success\": false}";

        assertThat(verifier.accepts(url(), "t")).isFalse();
    }

    @Test
    void anAnswerWithoutSuccessRejects() {
        body = "{}";

        assertThat(verifier.accepts(url(), "t")).isFalse();
    }

    @Test
    void aNonOkStatusRejects() {
        status = 401;
        body = "{\"success\": true}";

        assertThat(verifier.accepts(url(), "t")).isFalse();
    }

    @Test
    void anUnreachableVerifierDoesNotBlockTheMint() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }

        assertThat(verifier.accepts("http://127.0.0.1:" + closedPort + "/verify", "t")).isTrue();
    }

    @Test
    void anUnreadableAnswerDoesNotBlockTheMint() {
        body = "<html>oops</html>";

        assertThat(verifier.accepts(url(), "t")).isTrue();
    }

    @Test
    void aUrlThatCannotBeUsedFailsClosed() {
        assertThat(verifier.accepts("not a url", "t")).isFalse();
    }
}
