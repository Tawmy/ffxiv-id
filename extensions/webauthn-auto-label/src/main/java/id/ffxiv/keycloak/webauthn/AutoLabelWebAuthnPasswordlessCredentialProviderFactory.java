package id.ffxiv.keycloak.webauthn;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * Replaces Keycloak's built-in passwordless WebAuthn credential provider:
 * same provider ID, higher order, so Keycloak picks this factory instead
 * (see org.keycloak.provider.ProviderManager#compareFactories).
 */
public class AutoLabelWebAuthnPasswordlessCredentialProviderFactory extends WebAuthnPasswordlessCredentialProviderFactory {

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new AutoLabelWebAuthnPasswordlessCredentialProvider(session, getMetadataService(), createOrGetObjectConverter());
    }

    @Override
    public int order() {
        return 100;
    }
}
