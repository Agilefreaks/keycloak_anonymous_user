package com.agilefreaks.keycloak.anonymous;

/** Asks a verifier whether an app attestation token is genuine. */
@FunctionalInterface
interface AttestationVerifier {

    boolean accepts(String verifyUrl, String token);
}
