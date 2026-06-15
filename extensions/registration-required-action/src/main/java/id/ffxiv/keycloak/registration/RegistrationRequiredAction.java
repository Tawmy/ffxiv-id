package id.ffxiv.keycloak.registration;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Registration form action that flags the freshly created user with a configurable required
 * action (e.g. {@code webauthn-register-passwordless}).
 *
 * <p>This exists because Keycloak only offers a realm-wide "default action" toggle, which is
 * applied to <em>every</em> new user at creation time — including users federated from identity
 * providers on first broker login (see {@code JpaUserProvider.addUser} /
 * {@code IdpCreateUserIfUniqueAuthenticator}). To require an action for registration-form users
 * only, the default toggle is turned off and this action is added to the registration flow, with
 * the required action to assign supplied via the execution's config ({@link #REQUIRED_ACTION}).
 */
public class RegistrationRequiredAction implements FormAction, FormActionFactory, ConfiguredProvider {

    public static final String PROVIDER_ID = "registration-required-action";

    static final String REQUIRED_ACTION = "required_action";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        // No UI; this action only mutates the user on success.
    }

    @Override
    public void validate(ValidationContext context) {
        context.success();
    }

    @Override
    public void success(FormContext context) {
        String requiredAction = getConfiguredRequiredAction(context);
        if (requiredAction == null) {
            return;
        }

        UserModel user = context.getUser();
        if (user != null) {
            user.addRequiredAction(requiredAction);
        } else {
            context.getAuthenticationSession().addRequiredAction(requiredAction);

        }
    }

    private static String getConfiguredRequiredAction(FormContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return null;
        }
        String value = config.getConfig().get(REQUIRED_ACTION);
        return (value == null || value.isBlank()) ? null : value.trim();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Nothing to configure up front.
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public String getDisplayType() {
        return "Registration Required Action";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public String getHelpText() {
        return "Assigns a configurable required action to users who complete the registration "
                + "form, without affecting users created through identity providers.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty requiredAction = new ProviderConfigProperty();
        requiredAction.setName(REQUIRED_ACTION);
        requiredAction.setLabel("Required action alias");
        requiredAction.setType(ProviderConfigProperty.STRING_TYPE);
        requiredAction.setHelpText("Alias of the required action to assign to the user "
                + "(e.g. webauthn-register-passwordless, CONFIGURE_TOTP).");
        return List.of(requiredAction);
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
