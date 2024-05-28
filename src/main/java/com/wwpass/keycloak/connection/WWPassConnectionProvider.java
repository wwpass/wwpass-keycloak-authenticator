package com.wwpass.keycloak.connection;

import org.keycloak.provider.Provider;

import com.wwpass.keycloak.ticket.WWPassTicket;

public interface WWPassConnectionProvider extends Provider {
    WWPassTicket getTicket(String configId);

    String getPUID(String configId, String ticket);
}
