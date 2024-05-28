package com.wwpass.keycloak.connection;

import org.jboss.logging.Logger;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class WWPassConnectionFactoryImpl implements WWPassConnectionFactory {
    private static final Logger LOGGER = Logger.getLogger(WWPassConnectionFactoryImpl.class);

    @Override
    public WWPassConnectionProvider create(KeycloakSession session) {
        LOGGER.info("Create");
        return new WWPassConnectionProviderImpl(session);
    }

    @Override
    public void init(Scope config) {
        LOGGER.info("init");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LOGGER.info("postInit");
    }

    @Override
    public void close() {
        LOGGER.info("close");
    }

    @Override
    public String getId() {
        LOGGER.info("getId");
        return "WWPassConnectionProvider";
    }
}
