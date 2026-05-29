package id.ffxiv.keycloak.steam;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;

/**
 * OpenID 2.0 identity provider for Steam.
 * Steam is the only mainstream OpenID 2.0 provider still in use. Verification is
 * delegated to Steam via {@code openid.mode=check_authentication} (OpenID 2.0
 * §11.4.2), so this provider does not need to implement Diffie-Hellman associations
 * or local signature checks.
 */
public class SteamIdentityProvider
        extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(SteamIdentityProvider.class);

    private static final String OPENID_NS = "http://specs.openid.net/auth/2.0";
    private static final String OPENID_IDENTIFIER_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";
    private static final String STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
    private static final String STEAM_ID_PREFIX = "https://steamcommunity.com/openid/id/";
    // Steam OpenID logs in individual accounts, whose SteamID64 is always 17 digits.
    private static final Pattern STEAM_ID_PATTERN = Pattern.compile("\\d{17}");

    // Steam's signature must cover every field we read from the response.
    private static final List<String> REQUIRED_SIGNED_FIELDS =
            List.of("op_endpoint", "claimed_id", "identity", "return_to", "response_nonce");

    // Steam keeps answering check_authentication with is_valid:true for an assertion it has
    // already verified, so the signed response_nonce is our only replay defense at the OpenID
    // layer: reject it once it is older than this window, and remember it for the same window.
    private static final Duration NONCE_VALIDITY = Duration.ofMinutes(5);
    // Tolerated forward clock skew between Steam and this server when reading the nonce timestamp.
    private static final Duration NONCE_CLOCK_SKEW = Duration.ofMinutes(1);
    private static final String NONCE_SINGLE_USE_PREFIX = "steam-openid-nonce:";

    public SteamIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
    }

    // Steam is OpenID 2.0, not OAuth2: there are no scopes to request.
    @Override
    protected String getDefaultScopes() {
        return "";
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        String returnTo = UriBuilder.fromUri(request.getRedirectUri())
                .queryParam("state", request.getState().getEncoded())
                .build()
                .toString();

        URI returnUri = URI.create(returnTo);
        String realm = returnUri.getScheme() + "://" + returnUri.getAuthority() + "/";

        URI redirect = UriBuilder.fromUri(STEAM_OPENID_URL)
                .queryParam("openid.ns", OPENID_NS)
                .queryParam("openid.mode", "checkid_setup")
                .queryParam("openid.return_to", returnTo)
                .queryParam("openid.realm", realm)
                .queryParam("openid.identity", OPENID_IDENTIFIER_SELECT)
                .queryParam("openid.claimed_id", OPENID_IDENTIFIER_SELECT)
                .build();

        return Response.seeOther(redirect).build();
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.noContent().build();
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity,
                                  UserSessionModel userSession, UserModel user) {
        return Response.noContent().build();
    }

    static boolean verifyWithSteam(KeycloakSession session, MultivaluedMap<String, String> params)
            throws IOException {
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(STEAM_OPENID_URL);
        params.forEach((key, values) -> {
            if (!key.startsWith("openid.") || values.isEmpty()) {
                return;
            }
            String value = "openid.mode".equals(key) ? "check_authentication" : values.getFirst();
            request.param(key, value);
        });

        String body = request.asString();
        return body != null && body.lines().anyMatch("is_valid:true"::equals);
    }

    static String extractSteamId(String claimedId) {
        if (claimedId == null || !claimedId.startsWith(STEAM_ID_PREFIX)) {
            throw new IdentityBrokerException("Invalid Steam claimed_id: " + claimedId);
        }
        String steamId = claimedId.substring(STEAM_ID_PREFIX.length());
        if (!STEAM_ID_PATTERN.matcher(steamId).matches()) {
            throw new IdentityBrokerException("Invalid Steam claimed_id: " + claimedId);
        }
        return steamId;
    }

    /**
     * Confirms that the (already signature-verified) assertion was issued by Steam for this
     * exact login attempt and has not been replayed. Must run only after {@link #verifyWithSteam}
     * returns true, since it trusts {@code openid.signed} and the fields it lists.
     */
    static void validateSignedAssertion(KeycloakSession session, UriInfo uriInfo, String state) {
        MultivaluedMap<String, String> params = uriInfo.getQueryParameters();

        String opEndpoint = params.getFirst("openid.op_endpoint");
        if (!STEAM_OPENID_URL.equals(opEndpoint)) {
            throw new IdentityBrokerException("Unexpected OpenID op_endpoint: " + opEndpoint);
        }

        String signed = params.getFirst("openid.signed");
        List<String> signedFields = signed == null ? List.of() : Arrays.asList(signed.split(","));
        if (!new HashSet<>(signedFields).containsAll(REQUIRED_SIGNED_FIELDS)) {
            throw new IdentityBrokerException("Steam did not sign the required fields: " + signed);
        }

        URI returnTo = parseUri(requireParam(params, "openid.return_to"));
        URI endpoint = uriInfo.getAbsolutePath();
        if (!endpoint.getScheme().equals(returnTo.getScheme())
                || !endpoint.getAuthority().equals(returnTo.getAuthority())
                || !endpoint.getPath().equals(returnTo.getPath())) {
            throw new IdentityBrokerException("openid.return_to does not match the callback URL: " + returnTo);
        }
        if (!state.equals(queryParam(returnTo, "state"))) {
            throw new IdentityBrokerException("openid.return_to is bound to a different login attempt");
        }

        rejectStaleOrReplayedNonce(session, requireParam(params, "openid.response_nonce"));
    }

    /**
     * Steam's {@code openid.response_nonce} starts with an RFC 3339 UTC timestamp (OpenID 2.0
     * §10.1), e.g. {@code 2026-05-28T12:34:56Z} followed by unique characters. We reject the
     * assertion if that timestamp is older than {@link #NONCE_VALIDITY} or more than
     * {@link #NONCE_CLOCK_SKEW} in the future, then consume the nonce via the single-use store so
     * the same assertion cannot be replayed.
     * The store entry must outlive the acceptance window, otherwise a nonce could be replayed after
     * its entry expired but while it was still inside the window. It therefore lives for the full
     * window ({@code NONCE_VALIDITY + NONCE_CLOCK_SKEW}).
     */
    static void rejectStaleOrReplayedNonce(KeycloakSession session, String nonce) {
        Instant issued;
        try {
            issued = Instant.parse(nonce.substring(0, nonce.indexOf('Z') + 1));
        } catch (DateTimeException e) {
            throw new IdentityBrokerException("Malformed Steam response_nonce");
        }
        Duration age = Duration.between(issued, Instant.now());
        if (age.compareTo(NONCE_VALIDITY) > 0 || age.compareTo(NONCE_CLOCK_SKEW.negated()) < 0) {
            throw new IdentityBrokerException("Steam assertion is outside the accepted time window");
        }
        long ttlSeconds = NONCE_VALIDITY.plus(NONCE_CLOCK_SKEW).toSeconds();
        if (!session.singleUseObjects().putIfAbsent(NONCE_SINGLE_USE_PREFIX + nonce, ttlSeconds)) {
            throw new IdentityBrokerException("Steam assertion has already been used");
        }
    }

    private static String requireParam(MultivaluedMap<String, String> params, String key) {
        String value = params.getFirst(key);
        if (value == null) {
            throw new IdentityBrokerException("Missing " + key);
        }
        return value;
    }

    private static URI parseUri(String value) {
        try {
            return new URI(value);
        } catch (URISyntaxException e) {
            throw new IdentityBrokerException("Malformed URI: " + value);
        }
    }

    // Reads a single query parameter from the signed return_to; we only ever need "state",
    // so a hand-rolled parser is preferred over pulling in a URI-encoding dependency.
    static String queryParam(URI uri, String name) {
        String query = uri.getRawQuery();
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq >= 0 && name.equals(pair.substring(0, eq))) {
                return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /**
     * Steam's OpenID 2.0 reply lands on a JAX-RS sub-resource returned by {@link #callback}.
     * Keycloak's {@code IdentityBrokerService.getEndpoint} declares an {@code Object} return type,
     * so RESTEasy Reactive can only dispatch to a sub-resource class it discovered while indexing
     * {@code keycloak-services} at {@code kc.sh build} time. Extending the already-indexed
     * {@link AbstractOAuth2IdentityProvider.Endpoint} (rather than a standalone class) is what makes
     * this endpoint resolvable; a class unknown to that index yields HTTP 405 on the callback.
     * The {@code @GET authResponse} signature must match the parent exactly for the override to take
     * effect, so the {@code openid.*} fields are read from the request URI instead of {@code @QueryParam}.
     */
    protected static class Endpoint extends AbstractOAuth2IdentityProvider.Endpoint {

        private final SteamIdentityProvider provider;

        Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
                 SteamIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = provider;
        }

        @GET
        @Override
        public Response authResponse(@QueryParam("state") String state,
                                     @QueryParam("code") String authorizationCode,
                                     @QueryParam("error") String error,
                                     @QueryParam("error_description") String errorDescription) {
            IdentityProviderModel config = provider.getConfig();

            if (state == null) {
                return callback.error(config, "Missing state parameter");
            }

            AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
            session.getContext().setAuthenticationSession(authSession);

            UriInfo uriInfo = session.getContext().getUri();
            MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
            String mode = params.getFirst("openid.mode");

            if ("cancel".equals(mode)) {
                return callback.cancelled(config);
            }
            if (!"id_res".equals(mode)) {
                LOG.warnf("Unexpected openid.mode from Steam: %s", mode);
                return callback.error(config, "Unexpected OpenID response from Steam");
            }

            try {
                if (!verifyWithSteam(session, params)) {
                    return callback.error(config, "Steam rejected the OpenID assertion");
                }

                validateSignedAssertion(session, uriInfo, state);

                String steamId = extractSteamId(params.getFirst("openid.claimed_id"));

                BrokeredIdentityContext identity = new BrokeredIdentityContext(steamId, config);
                identity.setUsername(steamId);
                identity.setUserAttribute("steamId", steamId);
                identity.setIdp(provider);
                identity.setAuthenticationSession(authSession);

                return callback.authenticated(identity);
            } catch (IOException e) {
                LOG.error("Failed to contact Steam for OpenID verification", e);
                return callback.error(config, "Could not contact Steam to verify the assertion");
            } catch (IdentityBrokerException e) {
                LOG.error("Steam OpenID verification failed", e);
                return callback.error(config, "Steam OpenID verification failed");
            }
        }
    }
}
