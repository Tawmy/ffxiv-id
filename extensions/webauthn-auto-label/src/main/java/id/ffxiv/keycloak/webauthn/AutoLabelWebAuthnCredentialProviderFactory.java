package id.ffxiv.keycloak.webauthn;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * Replaces Keycloak's built-in two-factor WebAuthn credential provider:
 * same provider ID, higher order, so Keycloak picks this factory instead
 * (see org.keycloak.provider.ProviderManager#compareFactories).
 */
public class AutoLabelWebAuthnCredentialProviderFactory extends WebAuthnCredentialProviderFactory {

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new AutoLabelWebAuthnCredentialProvider(session, getMetadataService(), createOrGetObjectConverter());
    }

    @Override
    public int order() {
        return 100;
    }
}
