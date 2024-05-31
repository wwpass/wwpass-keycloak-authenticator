# WWPass Identity Provider

## Design considerations

To make a custom endpoint for getting WWPass ticket we implement custom SPI
`com.wwpass.keycloak.connection.WWPassConnectionFactory` as a service to access WWPass API
and `org.keycloak.services.resource.RealmResourceProviderFactory` to implement that endpoint.

## Installation

1. First, Keycloak must be running.
   See [Getting Started](https://github.com/keycloak/keycloak#getting-started),
   or you can build distribution
   from [source](https://github.com/keycloak/keycloak/blob/master/docs/building.md).

2. Set KEYCLOAK_HOME to your installation directory:

   ```console
   $ export KEYCLOAK_HOME="<path_to_keycloak_root>"
   ```

3. Execute the following. This will build the IdP:

   ```console
   $ mvn clean package
   ```

4. Deploy jar:
   ```console
   $ cp target/wwpass-idp.jar "$KEYCLOAK_HOME/providers/"
   ```

5. Restart (or start) Keycloak.

## Configuration

1. Go to the **Identity Providers** menu and add `WWPass authentication` provider.

2. Copy contents of your WWPass certificate and private key.
   Toggle PIN if necessary.
   Choose an alias and save the configuration.

3. Go to **Authentication** menu and configure authentication flow to use WWPass Identity provider.
   As WWPass does not provide trusted email or any other user information you may want to set up
   an action like `Verify Existing Account by Email` in the flow after WWPass Identity provider.

## Further setup

You can find the detailed instructions on the furhter configuration of Keycloak with WWPass in the documentation
[here](https://docs.wwpass.com/docs/keycloak/).
