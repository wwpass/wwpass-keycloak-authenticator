package com.wwpass.keycloak.ticket;

public final class WWPassTicket {
    public final String ticket;
    public final int ttl;

    public WWPassTicket(String ticket, int ttl) {
        this.ticket = ticket;
        this.ttl = ttl;
    }
}
