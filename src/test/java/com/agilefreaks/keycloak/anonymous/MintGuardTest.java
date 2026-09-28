package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MintGuardTest {

    private static final String REALM = "realm-1";
    private static final String IP = "203.0.113.7";
    private static final String HEADER = "X-App-Attestation";
    private static final String VERIFY_URL = "https://verify.example.com/check";

    private final MutableClock clock = new MutableClock(1_700_000_000L);
    private final InMemoryCounterStore store = new InMemoryCounterStore(clock);
    private final List<String> verified = new ArrayList<>();
    private boolean verifierSays = true;

    private final AttestationVerifier verifier = (url, token) -> {
        verified.add(url + " " + token);
        return verifierSays;
    };

    private MintGuard guard(MintOptions options) {
        return new MintGuard(options, store, clock, verifier);
    }

    private static MintOptions attested(String verifyUrl) {
        return new MintOptions(30, 2000, HEADER, verifyUrl);
    }

    @Test
    void withNoHeaderConfiguredNothingIsAskedOfTheClient() {
        MintRateGate.Decision decision = guard(new MintOptions(30, 2000, "", "")).check(REALM, IP, name -> null);

        assertThat(decision.allowed()).isTrue();
        assertThat(verified).isEmpty();
    }

    @Test
    void aMissingAttestationHeaderIsRefused() {
        assertThat(guard(attested(VERIFY_URL)).check(REALM, IP, name -> null).refusal())
                .isEqualTo(MintRefusal.ATTESTATION_MISSING);
        assertThat(guard(attested(VERIFY_URL)).check(REALM, IP, name -> "  ").refusal())
                .isEqualTo(MintRefusal.ATTESTATION_MISSING);
        assertThat(verified).isEmpty();
    }

    @Test
    void theHeaderIsReadByItsConfiguredName() {
        MintRateGate.Decision decision = guard(attested(VERIFY_URL))
                .check(REALM, IP, name -> HEADER.equals(name) ? "token-1" : null);

        assertThat(decision.allowed()).isTrue();
        assertThat(verified).containsExactly(VERIFY_URL + " token-1");
    }

    @Test
    void theVerifierRejectingTheTokenRefusesTheMint() {
        verifierSays = false;

        assertThat(guard(attested(VERIFY_URL)).check(REALM, IP, name -> "token-1").refusal())
                .isEqualTo(MintRefusal.ATTESTATION);
    }

    @Test
    void withoutAVerifyUrlThePresenceOfTheHeaderIsEnough() {
        assertThat(guard(attested("")).check(REALM, IP, name -> "anything").allowed()).isTrue();
        assertThat(verified).isEmpty();
    }

    @Test
    void anAttestationRefusalChargesNoCounter() {
        verifierSays = false;
        MintGuard guard = guard(new MintOptions(1, 1, HEADER, VERIFY_URL));
        guard.check(REALM, IP, name -> "bad");
        guard.check(REALM, IP, name -> null);

        verifierSays = true;

        assertThat(guard.check(REALM, IP, name -> "good").allowed()).isTrue();
    }

    @Test
    void theCountersApplyOnceAttestationPasses() {
        MintGuard guard = guard(new MintOptions(1, 2000, HEADER, VERIFY_URL));
        guard.check(REALM, IP, name -> "token");

        MintRateGate.Decision second = guard.check(REALM, IP, name -> "token");

        assertThat(second.refusal()).isEqualTo(MintRefusal.THROTTLED_IP);
        assertThat(second.retryAfterSeconds()).isPositive();
    }
}
