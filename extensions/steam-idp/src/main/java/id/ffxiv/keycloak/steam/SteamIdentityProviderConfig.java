package id.ffxiv.keycloak.steam;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * Steam-specific provider configuration. OpenID 2.0 only yields the SteamID64, so an optional
 * Steam Web API key is used to enrich the brokered identity with the player's persona name and
 * avatar via {@code ISteamUser/GetPlayerSummaries}. When no key is configured the provider behaves
 * exactly as before and only the SteamID is mapped.
 */
public class SteamIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public static final String API_KEY = "apiKey";

    public SteamIdentityProviderConfig() {
        super();
    }

    public SteamIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getApiKey() {
        return getConfig().get(API_KEY);
    }

    public void setApiKey(String apiKey) {
        getConfig().put(API_KEY, apiKey);
    }
}
