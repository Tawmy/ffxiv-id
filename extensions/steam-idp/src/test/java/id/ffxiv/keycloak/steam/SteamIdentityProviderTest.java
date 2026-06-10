package id.ffxiv.keycloak.steam;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.mockito.MockedStatic;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SteamIdentityProviderTest {

    private static final String STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
    private static final String STEAM_ID_PREFIX = "https://steamcommunity.com/openid/id/";
    private static final String CALLBACK = "https://id.ffxiv.id/realms/ffxiv/broker/steam/endpoint";
    private static final String SIGNED_FIELDS =
            "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle";

    // --- extractSteamId ------------------------------------------------------

    @Test
    void extractSteamId_returnsIdFromValidClaimedId() {
        String claimedId = "https://steamcommunity.com/openid/id/76561198031087104";
        assertEquals("76561198031087104", SteamIdentityProvider.extractSteamId(claimedId));
    }

    @Test
    void extractSteamId_rejectsNull() {
        assertThrows(IdentityBrokerException.class, () -> SteamIdentityProvider.extractSteamId(null));
    }

    @Test
    void extractSteamId_rejectsForeignPrefix() {
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.extractSteamId("https://evil.example/openid/id/123"));
    }

    @Test
    void extractSteamId_rejectsEmptyId() {
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.extractSteamId("https://steamcommunity.com/openid/id/"));
    }

    @Test
    void extractSteamId_rejectsNonNumericId() {
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.extractSteamId("https://steamcommunity.com/openid/id/notasteamid"));
    }

    @Test
    void extractSteamId_rejectsWrongLengthId() {
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.extractSteamId("https://steamcommunity.com/openid/id/12345"));
    }

    // --- queryParam ----------------------------------------------------------

    @Test
    void queryParam_readsAndDecodesValue() {
        URI uri = URI.create(CALLBACK + "?state=a%2Bb&other=x");
        assertEquals("a+b", SteamIdentityProvider.queryParam(uri, "state"));
    }

    @Test
    void queryParam_returnsNullWhenAbsent() {
        assertNull(SteamIdentityProvider.queryParam(URI.create(CALLBACK + "?foo=bar"), "state"));
    }

    @Test
    void queryParam_returnsNullWhenNoQuery() {
        assertNull(SteamIdentityProvider.queryParam(URI.create(CALLBACK), "state"));
    }

    // --- rejectStaleOrReplayedNonce ------------------------------------------

    @Test
    void nonce_acceptsFreshNonce() {
        assertDoesNotThrow(() ->
                SteamIdentityProvider.rejectStaleOrReplayedNonce(sessionAcceptingNonce(), nonceAt(Instant.now())));
    }

    @Test
    void nonce_rejectsStaleTimestamp() {
        String stale = nonceAt(Instant.now().minus(Duration.ofMinutes(10)));
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.rejectStaleOrReplayedNonce(sessionAcceptingNonce(), stale));
    }

    @Test
    void nonce_rejectsFutureTimestampBeyondSkew() {
        String future = nonceAt(Instant.now().plus(Duration.ofMinutes(10)));
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.rejectStaleOrReplayedNonce(sessionAcceptingNonce(), future));
    }

    @Test
    void nonce_acceptsFutureTimestampWithinSkew() {
        String nearFuture = nonceAt(Instant.now().plus(Duration.ofSeconds(30)));
        assertDoesNotThrow(() ->
                SteamIdentityProvider.rejectStaleOrReplayedNonce(sessionAcceptingNonce(), nearFuture));
    }

    @Test
    void nonce_rejectsMalformedTimestamp() {
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.rejectStaleOrReplayedNonce(sessionAcceptingNonce(), "not-a-timestamp"));
    }

    @Test
    void nonce_rejectsReplay() {
        KeycloakSession session = mock(KeycloakSession.class);
        SingleUseObjectProvider store = mock(SingleUseObjectProvider.class);
        when(session.singleUseObjects()).thenReturn(store);
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(false);

        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.rejectStaleOrReplayedNonce(session, nonceAt(Instant.now())));
    }

    // --- validateSignedAssertion ---------------------------------------------

    @Test
    void validate_acceptsWellFormedAssertion() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        assertDoesNotThrow(() ->
                SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsUnexpectedOpEndpoint() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        params.putSingle("openid.op_endpoint", "https://evil.example/openid/login");
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsMissingRequiredSignedField() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        params.putSingle("openid.signed", "op_endpoint,identity,return_to,response_nonce");
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsMissingSignedParameter() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        params.remove("openid.signed");
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsMissingReturnTo() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        params.remove("openid.return_to");
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsReturnToHostMismatch() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        params.putSingle("openid.return_to", "https://evil.example/realms/ffxiv/broker/steam/endpoint?state=state-123");
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsReturnToPathMismatch() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        params.putSingle("openid.return_to",
                "https://id.ffxiv.id/realms/ffxiv/broker/other/endpoint?state=state-123");
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "state-123"));
    }

    @Test
    void validate_rejectsStateMismatch() {
        MultivaluedMap<String, String> params = validParams("state-123", nonceAt(Instant.now()));
        assertThrows(IdentityBrokerException.class,
                () -> SteamIdentityProvider.validateSignedAssertion(sessionAcceptingNonce(), uriInfo(params), "different-state"));
    }

    // --- verifyWithSteam -----------------------------------------------------

    @Test
    void verify_acceptsIsValidTrue() throws Exception {
        assertTrue(runVerify("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n", paramsToVerify()).valid());
    }

    @Test
    void verify_rejectsIsValidFalse() throws Exception {
        assertFalse(runVerify("ns:http://specs.openid.net/auth/2.0\nis_valid:false\n", paramsToVerify()).valid());
    }

    @Test
    void verify_rejectsNullBody() throws Exception {
        assertFalse(runVerify(null, paramsToVerify()).valid());
    }

    @Test
    void verify_forwardsOpenidParamsAsCheckAuthentication() throws Exception {
        Map<String, String> forwarded = runVerify("is_valid:true", paramsToVerify()).forwarded();

        assertEquals("check_authentication", forwarded.get("openid.mode"));
        assertEquals("76561198031087104", forwarded.get("openid.claimed_id").substring(STEAM_ID_PREFIX.length()));
        assertEquals("sig-value", forwarded.get("openid.sig"));
        assertFalse(forwarded.containsKey("nonsense"), "non-openid params must not be forwarded");
        assertFalse(forwarded.containsKey("openid.empty"), "params without a value must not be forwarded");
    }

    // --- fetchPlayerSummary --------------------------------------------------

    private static final String PLAYER_SUMMARY_BODY = """
            {"response":{"players":[{
              "steamid":"76561198031087104",
              "personaname":"Tawmy",
              "profileurl":"https://steamcommunity.com/id/tawmy/",
              "avatar":"https://cdn.example/avatar.jpg",
              "avatarmedium":"https://cdn.example/avatar_medium.jpg",
              "avatarfull":"https://cdn.example/avatar_full.jpg"
            }]}}""";

    @Test
    void fetchPlayer_returnsNullWhenApiKeyMissing() {
        assertNull(SteamIdentityProvider.fetchPlayerSummary(mock(KeycloakSession.class), null, "76561198031087104"));
        assertNull(SteamIdentityProvider.fetchPlayerSummary(mock(KeycloakSession.class), "  ", "76561198031087104"));
    }

    @Test
    void fetchPlayer_mapsPersonaAvatarAndProfileUrl() throws Exception {
        SteamIdentityProvider.SteamPlayer player = runFetch(PLAYER_SUMMARY_BODY);
        assertEquals("Tawmy", player.personaName());
        assertEquals("https://cdn.example/avatar_full.jpg", player.avatarUrl());
        assertEquals("https://steamcommunity.com/id/tawmy/", player.profileUrl());
    }

    @Test
    void fetchPlayer_fallsBackToSmallerAvatar() throws Exception {
        SteamIdentityProvider.SteamPlayer player = runFetch(
                "{\"response\":{\"players\":[{\"personaname\":\"Tawmy\",\"avatar\":\"https://cdn.example/a.jpg\"}]}}");
        assertEquals("Tawmy", player.personaName());
        assertEquals("https://cdn.example/a.jpg", player.avatarUrl());
        assertNull(player.profileUrl());
    }

    @Test
    void fetchPlayer_returnsNullForEmptyPlayerList() throws Exception {
        assertNull(runFetch("{\"response\":{\"players\":[]}}"));
    }

    @Test
    void fetchPlayer_returnsNullForNullBody() throws Exception {
        assertNull(runFetch(null));
    }

    @Test
    void fetchPlayer_returnsNullForMalformedJson() throws Exception {
        assertNull(runFetch("not json"));
    }

    // --- usernameFromPersona -------------------------------------------------

    private static final String STEAM_ID = "76561198031087104";

    private static String usernameFor(String persona) {
        return SteamIdentityProvider.usernameFromPersona(
                new SteamIdentityProvider.SteamPlayer(persona, null, null), STEAM_ID);
    }

    @Test
    void username_lowercasesPersona() {
        assertEquals("tawmy", usernameFor("Tawmy"));
    }

    @Test
    void username_replacesDisallowedCharactersWithUnderscore() {
        assertEquals("cool_gamer", usernameFor("Cool Gamer!"));
    }

    @Test
    void username_keepsAllowedSeparators() {
        assertEquals("a.b-c_d", usernameFor("a.b-c_d"));
    }

    @Test
    void username_trimsLeadingAndTrailingSeparators() {
        assertEquals("bob", usernameFor("❤Bob❤"));
    }

    @Test
    void username_fallsBackToSteamIdWhenPersonaHasNothingUsable() {
        assertEquals(STEAM_ID, usernameFor("！？"));
    }

    @Test
    void username_fallsBackToSteamIdWhenPersonaNull() {
        assertEquals(STEAM_ID, usernameFor(null));
    }

    @Test
    void username_fallsBackToSteamIdWhenPlayerNull() {
        assertEquals(STEAM_ID, SteamIdentityProvider.usernameFromPersona(null, STEAM_ID));
    }

    // --- updateBrokeredUser (re-sync on login) -------------------------------

    @Test
    void updateBrokeredUser_reappliesAttributesWhenForce() {
        UserModel user = mock(UserModel.class);
        SteamIdentityProvider provider = providerWithSyncMode(IdentityProviderSyncMode.FORCE);

        BrokeredIdentityContext context = new BrokeredIdentityContext("76561198031087104", provider.getConfig());
        context.setUserAttribute("steamPersona", "Tawmy");
        context.setUserAttribute("steamAvatar", "https://cdn.example/avatar_full.jpg");

        provider.updateBrokeredUser(mock(KeycloakSession.class), mock(RealmModel.class), user, context);

        verify(user).setAttribute("steamPersona", List.of("Tawmy"));
        verify(user).setAttribute("steamAvatar", List.of("https://cdn.example/avatar_full.jpg"));
    }

    @Test
    void updateBrokeredUser_doesNothingWhenNotForce() {
        UserModel user = mock(UserModel.class);
        SteamIdentityProvider provider = providerWithSyncMode(IdentityProviderSyncMode.IMPORT);

        BrokeredIdentityContext context = new BrokeredIdentityContext("76561198031087104", provider.getConfig());
        context.setUserAttribute("steamPersona", "Tawmy");

        provider.updateBrokeredUser(mock(KeycloakSession.class), mock(RealmModel.class), user, context);

        verify(user, never()).setAttribute(anyString(), org.mockito.ArgumentMatchers.anyList());
    }

    // --- helpers -------------------------------------------------------------

    private static SteamIdentityProvider providerWithSyncMode(IdentityProviderSyncMode mode) {
        SteamIdentityProviderConfig config = new SteamIdentityProviderConfig();
        config.setEnabled(true); // BrokeredIdentityContext rejects a disabled IdP config
        config.setSyncMode(mode);
        return new SteamIdentityProvider(mock(KeycloakSession.class), config);
    }

    private static SteamIdentityProvider.SteamPlayer runFetch(String responseBody) throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        SimpleHttp http = mock(SimpleHttp.class);
        SimpleHttpRequest request = mock(SimpleHttpRequest.class);

        when(request.asString()).thenReturn(responseBody);

        try (MockedStatic<SimpleHttp> simpleHttp = mockStatic(SimpleHttp.class)) {
            simpleHttp.when(() -> SimpleHttp.create(session)).thenReturn(http);
            when(http.doGet(anyString())).thenReturn(request);
            return SteamIdentityProvider.fetchPlayerSummary(session, "api-key", "76561198031087104");
        }
    }

    private record VerifyResult(boolean valid, Map<String, String> forwarded) {
    }

    private static MultivaluedMap<String, String> paramsToVerify() {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("openid.mode", "id_res");
        params.putSingle("openid.claimed_id", STEAM_ID_PREFIX + "76561198031087104");
        params.putSingle("openid.sig", "sig-value");
        params.putSingle("nonsense", "should-not-forward");
        params.put("openid.empty", List.of());
        return params;
    }

    private static VerifyResult runVerify(String responseBody, MultivaluedMap<String, String> params)
            throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        SimpleHttp http = mock(SimpleHttp.class);
        SimpleHttpRequest request = mock(SimpleHttpRequest.class);
        Map<String, String> forwarded = new LinkedHashMap<>();

        when(request.param(anyString(), anyString())).thenAnswer(invocation -> {
            forwarded.put(invocation.getArgument(0), invocation.getArgument(1));
            return request;
        });
        when(request.asString()).thenReturn(responseBody);

        try (MockedStatic<SimpleHttp> simpleHttp = mockStatic(SimpleHttp.class)) {
            simpleHttp.when(() -> SimpleHttp.create(session)).thenReturn(http);
            when(http.doPost(STEAM_OPENID_URL)).thenReturn(request);
            return new VerifyResult(SteamIdentityProvider.verifyWithSteam(session, params), forwarded);
        }
    }

    private static String nonceAt(Instant when) {
        return when.toString() + "Pp4mNg";
    }

    private static MultivaluedMap<String, String> validParams(String state, String nonce) {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("openid.op_endpoint", STEAM_OPENID_URL);
        params.putSingle("openid.signed", SIGNED_FIELDS);
        params.putSingle("openid.return_to", CALLBACK + "?state=" + state);
        params.putSingle("openid.response_nonce", nonce);
        return params;
    }

    private static UriInfo uriInfo(MultivaluedMap<String, String> params) {
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(params);
        when(uriInfo.getAbsolutePath()).thenReturn(URI.create(CALLBACK));
        return uriInfo;
    }

    private static KeycloakSession sessionAcceptingNonce() {
        KeycloakSession session = mock(KeycloakSession.class);
        SingleUseObjectProvider store = mock(SingleUseObjectProvider.class);
        when(session.singleUseObjects()).thenReturn(store);
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        return session;
    }
}
