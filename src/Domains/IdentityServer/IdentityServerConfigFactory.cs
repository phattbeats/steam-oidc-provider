using System.Collections.Generic;
using System.Linq;
using IdentityServer4;
using IdentityServer4.Models;

namespace SteamOpenIdConnectProvider.Domains.IdentityServer;

public static class IdentityServerConfigFactory
{
    public static IEnumerable<Client> GetClients(OpenIdConfig config)
    {
        var client = new Client
        {
            ClientId = config.ClientId,
            ClientName = config.ClientName,
            AllowedGrantTypes = GrantTypes.Code,
            RequireConsent = false,
            ClientSecrets =
            {
                new Secret(config.ClientSecret.Sha256())
            },
            AlwaysSendClientClaims = true,
            AlwaysIncludeUserClaimsInIdToken = true,

            // where to redirect to after login
            RedirectUris = config.RedirectUris.ToArray(),

            // where to redirect to after logout
            PostLogoutRedirectUris = config.PostLogoutRedirectUris.ToArray(),

            // phattbeats fork: PKCE (S256) is mandatory for the single confidential client (Authentik sends it)
            RequirePkce = true,
            AllowPlainTextPkce = false,
            AllowedScopes = new List<string>
            {
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Profile,
                // phattbeats fork: Authentik's OIDC source always asks for "openid email profile";
                // IdentityServer rejects unknown scopes, so allow email (Steam yields no email claim).
                IdentityServerConstants.StandardScopes.Email,
            }
        };
        yield return client;
    }

    public static IEnumerable<IdentityResource> GetIdentityResources()
    {
        return new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email()
        };
    }
}
