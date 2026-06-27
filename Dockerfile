ARG KEYCLOAK_VERSION=26.6.4

FROM maven:3-eclipse-temurin-21 AS extensions
COPY extensions /build
WORKDIR /build
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION AS builder
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_FEATURES_DISABLED=ciba,device-flow,kerberos
COPY --chown=keycloak:keycloak theme /opt/keycloak/themes/ffxiv
COPY --from=extensions /build/steam-idp/target/keycloak-steam-idp.jar /opt/keycloak/providers/
COPY --from=extensions /build/webauthn-auto-label/target/keycloak-webauthn-auto-label.jar /opt/keycloak/providers/
COPY --from=extensions /build/registration-required-action/target/keycloak-registration-required-action.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]