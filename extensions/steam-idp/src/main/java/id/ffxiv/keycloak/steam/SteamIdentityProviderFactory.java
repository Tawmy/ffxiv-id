package id.ffxiv.keycloak.steam;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class SteamIdentityProviderFactory
        extends AbstractIdentityProviderFactory<SteamIdentityProvider>
        implements SocialIdentityProviderFactory<SteamIdentityProvider> {

    public static final String PROVIDER_ID = "steam";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "Steam";
    }

    @Override
    public SteamIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new SteamIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }
}
