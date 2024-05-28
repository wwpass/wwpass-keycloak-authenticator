package com.wwpass.keycloak.ticket;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import com.wwpass.keycloak.connection.WWPassConnectionProvider;

final class WWPassTicketProvider implements RealmResourceProvider {
    private static final Logger LOGGER = Logger.getLogger(WWPassTicketProvider.class);
    private final KeycloakSession session;

    WWPassTicketProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("")
    @Operation(
            summary = "Ticket",
            description = "This endpoint returns WWPass ticket by provider alias"
    )
    @APIResponse(
            responseCode = "200",
            content = {
                    @Content(
                            schema = @Schema(
                                    implementation = Response.class,
                                    type = SchemaType.OBJECT
                            )
                    )}
    )
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public WWPassTicket get(@QueryParam("config") String id) {
        LOGGER.info("Getting ticket for config: " + id);
        return session.getProvider(WWPassConnectionProvider.class).getTicket(id);
    }

    @Override
    public void close() {
    }
}
