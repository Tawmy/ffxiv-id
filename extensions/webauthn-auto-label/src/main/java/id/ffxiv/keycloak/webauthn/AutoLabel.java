package id.ffxiv.keycloak.webauthn;

import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Labels new WebAuthn credentials with the authenticator provider name
 * resolved from the AAGUID (e.g. "1Password"), so the login theme can skip
 * the label prompt. Falls back to the submitted label for authenticators
 * Keycloak's metadata does not know. Duplicate labels (per credential type)
 * get a numeric suffix, e.g. "1Password (2)".
 *
 * <p>Shared by the passwordless and two-factor providers, which cannot share
 * a base class because they extend different Keycloak providers.
 */
final class AutoLabel {

    private static final String FALLBACK_LABEL = "Passkey";

    private AutoLabel() {
    }

    static void apply(WebAuthnMetadataService metadataService, UserModel user, String credentialType,
                      WebAuthnCredentialModel credentialModel) {
        String aaguid = credentialModel.getWebAuthnCredentialData().getAaguid();
        String base = metadataService.getAuthenticatorProvider(aaguid);
        if (base == null || base.isBlank()) {
            base = credentialModel.getUserLabel();
        }

        Set<String> existingLabels = user.credentialManager().getStoredCredentialsByTypeStream(credentialType)
                .map(CredentialModel::getUserLabel)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        credentialModel.setUserLabel(uniqueLabel(base, existingLabels));
    }

    static String uniqueLabel(String base, Set<String> existingLabels) {
        String trimmed = base == null ? "" : base.trim();
        if (trimmed.isEmpty()) {
            trimmed = FALLBACK_LABEL;
        }

        String label = trimmed;
        for (int i = 2; existingLabels.contains(label); i++) {
            label = trimmed + " (" + i + ")";
        }
        return label;
    }
}
