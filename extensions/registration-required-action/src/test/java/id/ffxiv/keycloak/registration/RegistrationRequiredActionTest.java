package id.ffxiv.keycloak.registration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.FormContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

class RegistrationRequiredActionTest {

    private static final String ALIAS = "webauthn-register-passwordless";

    private final RegistrationRequiredAction action = new RegistrationRequiredAction();

    private static AuthenticatorConfigModel config(Map<String, String> values) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(values);
        return config;
    }

    @Test
    void addsConfiguredRequiredActionToCreatedUser() {
        UserModel user = mock(UserModel.class);
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        FormContext context = mock(FormContext.class);
        when(context.getAuthenticatorConfig()).thenReturn(config(Map.of(RegistrationRequiredAction.REQUIRED_ACTION, ALIAS)));
        when(context.getUser()).thenReturn(user);

        action.success(context);

        verify(user).addRequiredAction(ALIAS);
        verify(authSession, never()).addRequiredAction(ALIAS);
    }

    @Test
    void fallsBackToAuthSessionWhenUserMissing() {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        FormContext context = mock(FormContext.class);
        when(context.getAuthenticatorConfig()).thenReturn(config(Map.of(RegistrationRequiredAction.REQUIRED_ACTION, ALIAS)));
        when(context.getUser()).thenReturn(null);
        when(context.getAuthenticationSession()).thenReturn(authSession);

        action.success(context);

        verify(authSession).addRequiredAction(ALIAS);
    }

    @Test
    void doesNothingWhenNotConfigured() {
        UserModel user = mock(UserModel.class);
        FormContext context = mock(FormContext.class);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(context.getUser()).thenReturn(user);

        action.success(context);

        verify(user, never()).addRequiredAction(ALIAS);
    }
}
