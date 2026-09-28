package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The mint guards' options, under {@code spi-oauth2-grant-type--anonymous--*}. */
class MintOptionsTest {

    @Test
    void theDefaults() {
        MintOptions defaults = MintOptions.from(MapScope.of());

        assertThat(defaults.maxMintsPerIpPerHour()).isEqualTo(30);
        assertThat(defaults.maxMintsPerRealmPerHour()).isEqualTo(2000);
        assertThat(defaults.startTokenHeader()).isEmpty();
        assertThat(defaults.startTokenVerifyUrl()).isEmpty();
    }

    @Test
    void everyOptionIsRead() {
        MintOptions set = MintOptions.from(MapScope.of(
                "max-mints-per-ip-per-hour", "5",
                "max-mints-per-realm-per-hour", "0",
                "start-token-header", " X-App-Attestation ",
                "start-token-verify-url", "https://verify.example.com/check"));

        assertThat(set.maxMintsPerIpPerHour()).isEqualTo(5);
        assertThat(set.maxMintsPerRealmPerHour()).isZero();
        assertThat(set.startTokenHeader()).isEqualTo("X-App-Attestation");
        assertThat(set.startTokenVerifyUrl()).isEqualTo("https://verify.example.com/check");
    }

    @Test
    void aLimitThatIsNotANumberStopsTheServerAndNamesTheOption() {
        assertThatThrownBy(() -> MintOptions.from(MapScope.of("max-mints-per-ip-per-hour", "lots")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("spi-oauth2-grant-type--anonymous--max-mints-per-ip-per-hour");
    }

    @Test
    void aNegativeLimitIsRefusedRatherThanReadAsOff() {
        assertThatThrownBy(() -> MintOptions.from(MapScope.of("max-mints-per-realm-per-hour", "-1")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("max-mints-per-realm-per-hour");
    }

    @Test
    void aVerifyUrlWithoutAHeaderWouldNeverBeCalledSoItStopsTheServer() {
        assertThatThrownBy(() -> MintOptions.from(MapScope.of("start-token-verify-url", "https://verify.example.com")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("start-token-header");
    }

    @Test
    void aVerifyUrlThatIsNotHttpStopsTheServer() {
        assertThatThrownBy(() -> MintOptions.from(MapScope.of(
                "start-token-header", "X-App-Attestation", "start-token-verify-url", "verify.example.com")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("start-token-verify-url");
        assertThatThrownBy(() -> MintOptions.from(MapScope.of(
                "start-token-header", "X-App-Attestation", "start-token-verify-url", "https://bad host/")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theFactoryReadsThemFromTheAnonymousScope() {
        System.setProperty("keycloak.oauth2-grant-type.anonymous.max-mints-per-ip-per-hour", "4");
        try {
            AnonymousGrantTypeFactory factory = new AnonymousGrantTypeFactory();
            factory.init(null);

            assertThat(factory.mintOptions().maxMintsPerIpPerHour()).isEqualTo(4);
        } finally {
            System.clearProperty("keycloak.oauth2-grant-type.anonymous.max-mints-per-ip-per-hour");
        }
    }
}
