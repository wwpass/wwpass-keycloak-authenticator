package com.wwpass.keycloak.idp;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public final class WWPassConfigurationRepresentation {

    @JsonProperty("certificate")
    private String certificate;

    @JsonProperty("privateKey")
    private String privateKey;

    @JsonProperty("usePIN")
    private boolean usePIN;
}
