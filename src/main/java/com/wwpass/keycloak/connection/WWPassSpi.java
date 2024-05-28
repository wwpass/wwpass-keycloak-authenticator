package com.wwpass.keycloak.connection;

import org.jboss.logging.Logger;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public final class WWPassSpi implements Spi {
    private static final Logger logger = Logger.getLogger(WWPassSpi.class);

    @Override
    public boolean isInternal() {
        logger.info("isInternal");
        return false;
    }

    @Override
    public String getName() {
        logger.info("getName");
        return "wwpass-connection";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        logger.info("getProviderClass");
        return WWPassConnectionProvider.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        logger.info("getProviderFactoryClass");
        return WWPassConnectionFactory.class;
    }
}
