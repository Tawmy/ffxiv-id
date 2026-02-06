ARG KEYCLOAK_VERSION=26.5.2

FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION AS builder
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_FEATURES_DISABLED=ciba,device-flow,kerberos,organization
COPY --chown=keycloak:keycloak theme /opt/keycloak/themes/ffxiv
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]