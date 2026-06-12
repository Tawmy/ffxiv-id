package id.ffxiv.keycloak.webauthn;

import com.webauthn4j.converter.util.ObjectConverter;
import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/**
 * Passwordless (passkey) variant of {@link AutoLabel}-based credential naming.
 */
public class AutoLabelWebAuthnPasswordlessCredentialProvider extends WebAuthnPasswordlessCredentialProvider {

    // The parent keeps its metadata service private, so hold our own reference.
    private final WebAuthnMetadataService metadataService;

    public AutoLabelWebAuthnPasswordlessCredentialProvider(KeycloakSession session,
                                                           WebAuthnMetadataService metadataService,
                                                           ObjectConverter objectConverter) {
        super(session, metadataService, objectConverter);
        this.metadataService = metadataService;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, WebAuthnCredentialModel credentialModel) {
        AutoLabel.apply(metadataService, user, getType(), credentialModel);
        return super.createCredential(realm, user, credentialModel);
    }
}
