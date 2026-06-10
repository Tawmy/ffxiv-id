package id.ffxiv.keycloak.steam;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

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
    public String getHelpText() {
        return "Steam (OpenID 2.0) identity provider.";
    }

    // Declares the provider's custom config so the admin console renders a form field for it.
    // Without this the apiKey is still honored (e.g. when set declaratively), it just isn't editable
    // in the console.
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(SteamIdentityProviderConfig.API_KEY)
                .label("Steam Web API key")
                .helpText("Steam Web API key used to fetch the player's persona name, avatar, and "
                        + "profile URL via ISteamUser/GetPlayerSummaries. Leave blank to map only the SteamID.")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()
                .build();
    }

    @Override
    public SteamIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new SteamIdentityProvider(session, new SteamIdentityProviderConfig(model));
    }

    @Override
    public SteamIdentityProviderConfig createConfig() {
        return new SteamIdentityProviderConfig();
    }
}
