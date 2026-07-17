package id.ffxiv.keycloak.webauthn;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.credential.dto.WebAuthnCredentialData;

import java.util.Set;
import java.util.stream.Stream;

import static id.ffxiv.keycloak.webauthn.AutoLabel.uniqueLabel;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AutoLabelTest {

    private static final String AAGUID = "bada5566-a7aa-401f-bd96-45619a55120d";
    private static final String TYPE = WebAuthnCredentialModel.TYPE_PASSWORDLESS;

    // --- apply ----------------------------------------------------------------

    @Test
    void apply_prefersMetadataProviderNameOverSubmittedLabel() {
        WebAuthnCredentialModel credential = newCredential("My Passkey");

        AutoLabel.apply(metadataResolving("1Password"), userWithStoredLabels(), TYPE, credential);

        verify(credential).setUserLabel("1Password");
    }

    @Test
    void apply_fallsBackToSubmittedLabelForUnknownAaguid() {
        WebAuthnCredentialModel credential = newCredential("My Passkey");

        AutoLabel.apply(metadataResolving(null), userWithStoredLabels(), TYPE, credential);

        verify(credential).setUserLabel("My Passkey");
    }

    @Test
    void apply_deduplicatesAgainstStoredLabelsIgnoringNullLabels() {
        WebAuthnCredentialModel credential = newCredential(null);

        AutoLabel.apply(metadataResolving("1Password"), userWithStoredLabels("1Password", null), TYPE, credential);

        verify(credential).setUserLabel("1Password (2)");
    }

    @Test
    void apply_fallsBackToPasskeyWhenMetadataBlankAndNoLabelSubmitted() {
        WebAuthnCredentialModel credential = newCredential(null);

        AutoLabel.apply(metadataResolving(""), userWithStoredLabels(), TYPE, credential);

        verify(credential).setUserLabel("Passkey");
    }

    private static WebAuthnCredentialModel newCredential(String submittedLabel) {
        WebAuthnCredentialModel credential = mock(WebAuthnCredentialModel.class);
        WebAuthnCredentialData data = mock(WebAuthnCredentialData.class);
        when(data.getAaguid()).thenReturn(AAGUID);
        when(credential.getWebAuthnCredentialData()).thenReturn(data);
        when(credential.getUserLabel()).thenReturn(submittedLabel);
        return credential;
    }

    private static WebAuthnMetadataService metadataResolving(String providerName) {
        WebAuthnMetadataService metadataService = mock(WebAuthnMetadataService.class);
        when(metadataService.getAuthenticatorProvider(AAGUID)).thenReturn(providerName);
        return metadataService;
    }

    private static UserModel userWithStoredLabels(String... labels) {
        UserModel user = mock(UserModel.class);
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credentialManager);
        when(credentialManager.getStoredCredentialsByTypeStream(TYPE)).thenAnswer(invocation ->
                Stream.of(labels).map(label -> {
                    CredentialModel stored = new CredentialModel();
                    stored.setUserLabel(label);
                    return stored;
                }));
        return user;
    }

    // --- uniqueLabel ------------------------------------------------------------

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
