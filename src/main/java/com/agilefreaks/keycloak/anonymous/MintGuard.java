package com.agilefreaks.keycloak.anonymous;

import java.time.Clock;
import java.util.function.UnaryOperator;

/**
 * Decides whether a guest may be minted, before anything is written: attestation first, then the
 * rate counters, so a request that fails attestation spends no budget.
 */
final class MintGuard {

    private final MintOptions options;
    private final MintRateGate rateGate;
    private final AttestationVerifier verifier;

    MintGuard(MintOptions options, CounterStore store, Clock clock, AttestationVerifier verifier) {
        this.options = options;
        this.rateGate = new MintRateGate(store, clock, options);
        this.verifier = verifier;
    }

    /** {@code header} looks a request header up by name. */
    MintRateGate.Decision check(String realmId, String ip, UnaryOperator<String> header) {
        String headerName = options.startTokenHeader();
        if (!headerName.isEmpty()) {
            String token = header.apply(headerName);
            if (token == null || token.isBlank()) {
                return MintRateGate.Decision.refused(MintRefusal.ATTESTATION_MISSING);
            }
            String verifyUrl = options.startTokenVerifyUrl();
            if (!verifyUrl.isEmpty() && !verifier.accepts(verifyUrl, token.trim())) {
                return MintRateGate.Decision.refused(MintRefusal.ATTESTATION);
            }
        }
        return rateGate.reserve(realmId, ip);
    }
}
