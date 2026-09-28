package com.agilefreaks.keycloak.anonymous;

import jakarta.ws.rs.core.Response;

/** Why a mint was refused: the {@code anon_reject} event detail, and the OAuth error the client sees. */
enum MintRefusal {
    ATTESTATION_MISSING("attestation_missing", Response.Status.BAD_REQUEST, "invalid_request",
            "this grant requires an app attestation header"),
    ATTESTATION("attestation", Response.Status.FORBIDDEN, "access_denied",
            "the app attestation was rejected"),
    THROTTLED_IP("throttled_ip", Response.Status.TOO_MANY_REQUESTS, "anonymous_throttled",
            "too many guest sessions from this address; try again later"),
    THROTTLED_REALM("throttled_realm", Response.Status.SERVICE_UNAVAILABLE, "temporarily_unavailable",
            "guest sessions are temporarily unavailable");

    final String detail;
    final Response.Status status;
    final String error;
    final String description;

    MintRefusal(String detail, Response.Status status, String error, String description) {
        this.detail = detail;
        this.status = status;
        this.error = error;
        this.description = description;
    }
}
