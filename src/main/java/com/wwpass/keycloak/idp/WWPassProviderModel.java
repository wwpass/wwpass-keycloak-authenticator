package com.wwpass.keycloak.idp;

import org.keycloak.models.IdentityProviderModel;

//NOTICE: https://github.com/keycloak/keycloak/issues/21891
public final class WWPassProviderModel extends IdentityProviderModel {
    public static final String PROVIDER_ID = "wwpass-authentication";
    public static final String CERT_CONFIG_NAME = "wwpass.credentials.certificate";
    public static final String KEY_CONFIG_NAME = "wwpass.credentials.key";
    public static final String PIN_CONFIG_NAME = "wwpass.pin";

    WWPassProviderModel(IdentityProviderModel model) {
        super(model);
    }

    WWPassProviderModel() {
        super();
    }

    public String getCertificate() {
        return getConfig().get(CERT_CONFIG_NAME);
    }

    public void setCertificate(String certificatePEM) {
        getConfig().put(CERT_CONFIG_NAME, certificatePEM);
    }

    public String getPrivateKey() {
        return getConfig().get(KEY_CONFIG_NAME);
    }

    public void setPrivateKey(String privateKeyPEM) {
        getConfig().put(KEY_CONFIG_NAME, privateKeyPEM);
    }

    public boolean getPIN() {
        return Boolean.valueOf(getConfig().get(PIN_CONFIG_NAME));
    }

    public void setPIN(boolean usePIN) {
        getConfig().put(PIN_CONFIG_NAME, String.valueOf(usePIN));
    }
}
