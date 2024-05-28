package com.wwpass.keycloak.idp;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;

import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.wwpass.keycloak.connection.WWPassConnectionProvider;

public final class WWPassIdentityProvider extends AbstractIdentityProvider<WWPassProviderModel> {
    private static final Logger LOGGER = Logger.getLogger(WWPassIdentityProvider.class);

    WWPassIdentityProvider(KeycloakSession session, WWPassProviderModel config) {
        super(session, config);
    }

    @Override
    public Response retrieveToken(KeycloakSession session,
                                  FederatedIdentityModel identity) {
        LOGGER.info("retrieveToken");
        return null;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback,
                           EventBuilder event) {
        LOGGER.info("callback");
        return new Endpoint(this, callback, event);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        LOGGER.info("Performing WWPass login");
        LoginFormsProvider form = session.getProvider(LoginFormsProvider.class);
        WWPassProviderModel cfg = this.getConfig();
        form.setAttribute("providerID", cfg.getAlias());
        form.setAttribute("state", request.getState().getEncoded());
        Response challenge = form.createForm("wwpass-login.ftl");
        return challenge;
    }

    protected static final class Endpoint {
        private final WWPassIdentityProvider parent;
        private final AuthenticationCallback callback;
        private final EventBuilder event;
        private final KeycloakSession session;

        Endpoint(WWPassIdentityProvider parent, AuthenticationCallback callback, EventBuilder event) {
            this.parent = parent;
            this.callback = callback;
            this.event = event;
            this.session = parent.session;
        }

        private Response errorWWPassLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }

        @GET
        public Response authResponse(@QueryParam("wwp_ticket") String ticket,
                                     @QueryParam("state") String state,
                                     @QueryParam("wwp_status") int status) {
            if (state == null) {
                return errorWWPassLogin("Login session expired");
            }
            try {
                AuthenticationSessionModel authSession =
                        this.callback.getAndVerifyAuthenticationSession(state);
                session.getContext().setAuthenticationSession(authSession);

                if (status == 200) {
                    String puid = session.getProvider(WWPassConnectionProvider.class)
                                    .getPUID(parent.getConfig().getAlias(), ticket);
                    LOGGER.info(String.format("PUID: %s", puid));
                    BrokeredIdentityContext federatedIdentity =
                            new BrokeredIdentityContext(puid);

                    federatedIdentity.setIdpConfig(parent.getConfig());
                    federatedIdentity.setIdp(parent);
                    federatedIdentity.setAuthenticationSession(authSession);
                    federatedIdentity.setUsername("wwpass-" + puid);

                    return callback.authenticated(federatedIdentity);
                }

                return callback.error("WWPass authentication failed");
            } catch (Exception e) {
                LOGGER.error("Failed to verify WWPass authentication", e);
            }
            return errorWWPassLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }
    }
}
