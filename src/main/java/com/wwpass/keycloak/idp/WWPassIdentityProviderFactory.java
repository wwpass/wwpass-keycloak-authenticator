package com.wwpass.keycloak.idp;

import java.io.InputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.util.JsonSerialization;

public final class WWPassIdentityProviderFactory extends AbstractIdentityProviderFactory<WWPassIdentityProvider> {

    public static final String PROVIDER_ID = "wwpass";

    @Override
    public String getName() {
        return "WWPass authentication";
    }

    @Override
    public WWPassIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WWPassIdentityProvider(session, new WWPassProviderModel(model));
    }

    @Override
    public WWPassProviderModel createConfig() {
        return new WWPassProviderModel();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, InputStream inputStream) {
        return parseConfig(inputStream);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().required(true).name("certificate")
                .label("Certificate")
                .helpText("WWPass registration client certificate on BASE64")
                .type(ProviderConfigProperty.TEXT_TYPE).add()
                .property().required(true).name("privateKey")
                .label("Private key")
                .helpText("WWPass registration client privet key on BASE64")
                .type(ProviderConfigProperty.TEXT_TYPE).add()
                .property().name("usePIN")
                .label("Use PIN")
                .helpText("PIN using")
                .type(ProviderConfigProperty.BOOLEAN_TYPE).add()
                .build();
    }

    private static Map<String, String> parseConfig(InputStream inputStream) {
        WWPassConfigurationRepresentation rep;
        try {
            rep = JsonSerialization.readValue(inputStream, WWPassConfigurationRepresentation.class);
        } catch (IOException e) {
            throw new RuntimeException("failed to load openid connect metadata", e);
        }
        WWPassProviderModel config = new WWPassProviderModel();
        config.setCertificate(rep.getCertificate());
        config.setPrivateKey(rep.getPrivateKey());
        config.setPIN(rep.isUsePIN());
        return config.getConfig();
    }

}

