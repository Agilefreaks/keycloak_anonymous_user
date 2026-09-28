package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class EnvTest {

    @AfterEach
    void restoreEnvironment() {
        Env.source = System::getenv;
    }

    private static void env(Map<String, String> values) {
        Env.source = values::get;
    }

    @Test
    void unsetAndBlankValuesFallBack() {
        env(Map.of("MOMA_BLANK", "   "));

        assertThat(Env.flag("MOMA_MISSING", true)).isTrue();
        assertThat(Env.flag("MOMA_BLANK", true)).isTrue();
        assertThat(Env.number("MOMA_MISSING", 7)).isEqualTo(7);
        assertThat(Env.number("MOMA_BLANK", 7)).isEqualTo(7);
    }

    @Test
    void flagsAreParsedLeniently() {
        env(Map.of("A", "true", "B", "TRUE", "C", " true ", "D", "false", "E", "nonsense"));

        assertThat(Env.flag("A", false)).isTrue();
        assertThat(Env.flag("B", false)).isTrue();
        assertThat(Env.flag("C", false)).isTrue();
        assertThat(Env.flag("D", true)).isFalse();
        // Anything that is not "true" reads as false — never as the fallback.
        assertThat(Env.flag("E", true)).isFalse();
    }

    @Test
    void numbersAreParsedAndBadOnesFallBackInsteadOfThrowing() {
        env(Map.of("N", "42", "SPACED", " 13 ", "JUNK", "six", "ZERO", "0"));

        assertThat(Env.number("N", 1)).isEqualTo(42);
        assertThat(Env.number("SPACED", 1)).isEqualTo(13);
        assertThat(Env.number("JUNK", 30)).isEqualTo(30);
        assertThat(Env.number("ZERO", 30)).isZero();
    }
}
