<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "social-providers.ftl" as identityProviders>
<#import "passkeys.ftl" as passkeys>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username') displayInfo=(realm.password && realm.registrationAllowed && !registrationDisabled??); section>
<!-- template: login-username.ftl -->

    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <div class="xiv-divider"></div>
        <#if realm.rememberMe && !usernameHidden??>
            <div id="kc-form">
                <div id="kc-form-wrapper">
                    <#if realm.password>
                        <form id="kc-form-login" class="${properties.kcFormClass!}">
                            <div class="${properties.kcFormGroupClass!}">
                                <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                            </div>
                        </form>
                    </#if>
                </div>
            </div>
        </#if>
        <@passkeys.conditionalUIData />

    <#elseif section = "info" >
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration">
                <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </#if>
    <#elseif section = "socialProviders" >
        <#if realm.password && social.providers?? && social.providers?has_content>
            <@identityProviders.show social=social />
        </#if>
    </#if>

</@layout.registrationLayout>
