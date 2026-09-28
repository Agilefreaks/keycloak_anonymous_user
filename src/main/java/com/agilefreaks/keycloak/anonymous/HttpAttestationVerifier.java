package com.agilefreaks.keycloak.anonymous;

import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * POSTs the token as {@code token} and reads {@code "success"} from the JSON answer. A verifier that
 * cannot be reached, or answers something unreadable, does not block the mint: the counters still
 * apply, and an outage there should not take guest sessions down with it.
 */
final class HttpAttestationVerifier implements AttestationVerifier {

    private static final Logger LOG = Logger.getLogger(HttpAttestationVerifier.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(4);
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    @Override
    public boolean accepts(String verifyUrl, String token) {
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(URI.create(verifyUrl))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)))
                    .build();
        } catch (IllegalArgumentException e) {
            // A URL that cannot be parsed will never work: failing open would disable the check for good.
            LOG.errorf(e, "attestation verify URL '%s' is not usable; refusing the mint", verifyUrl);
            return false;
        }

        try {
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                LOG.warnf("attestation verifier answered HTTP %d; refusing the mint", response.statusCode());
                return false;
            }
            return JsonSerialization.mapper.readTree(response.body()).path("success").asBoolean(false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn("attestation verification interrupted; allowing the mint");
            return true;
        } catch (Exception e) {
            LOG.warnf(e, "attestation verification failed; allowing the mint");
            return true;
        }
    }
}
