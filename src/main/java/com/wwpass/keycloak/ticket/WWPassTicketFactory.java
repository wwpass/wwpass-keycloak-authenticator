package com.wwpass.keycloak.ticket;

import java.text.MessageFormat;

import org.jboss.logging.Logger;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public final class WWPassTicketFactory implements RealmResourceProviderFactory {
    private static final Logger LOGGER = Logger.getLogger(WWPassTicketFactory.class);
    public static final String ID = "wwpass-ticket";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new WWPassTicketProvider(session);
    }

    @Override
    public void init(Scope config) {
        LOGGER.info(MessageFormat.format("init({0})", config));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LOGGER.info(MessageFormat.format("postInit({0})", factory.getClass()));
    }

    @Override
    public void close() {
        LOGGER.info("close()");
    }
}
