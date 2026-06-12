package id.ffxiv.keycloak.webauthn;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static id.ffxiv.keycloak.webauthn.AutoLabel.uniqueLabel;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AutoLabelTest {

    @Test
    void usesBaseLabelWhenFree() {
        assertEquals("1Password", uniqueLabel("1Password", Set.of()));
    }

    @Test
    void appendsSuffixWhenBaseLabelTaken() {
        assertEquals("1Password (2)", uniqueLabel("1Password", Set.of("1Password")));
    }

    @Test
    void incrementsSuffixUntilFree() {
        assertEquals("1Password (4)", uniqueLabel("1Password", Set.of("1Password", "1Password (2)", "1Password (3)")));
    }

    @Test
    void trimsBaseLabel() {
        assertEquals("iCloud Keychain", uniqueLabel("  iCloud Keychain  ", Set.of()));
    }

    @Test
    void fallsBackWhenBaseLabelNull() {
        assertEquals("Passkey", uniqueLabel(null, Set.of()));
    }

    @Test
    void fallsBackWithSuffixWhenBaseLabelBlank() {
        assertEquals("Passkey (2)", uniqueLabel("   ", Set.of("Passkey")));
    }
}
