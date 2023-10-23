using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Bff.Authentication;

public class OpenId
{
    public static void ConfigureOpenIdConnect(OpenIdConnectOptions options, IConfiguration config)
    {
        // Set the authority to your Auth0 domain
        options.Authority = $"https://{config["Auth0:Domain"]}";

        // Configure the Auth0 Client ID and Client Secret
        options.ClientId = config["Auth0:ClientId"];
        options.ClientSecret = config["Auth0:ClientSecret"];

        // Set response type to code
        options.ResponseType = OpenIdConnectResponseType.CodeIdToken;

        options.ResponseMode = OpenIdConnectResponseMode.FormPost;

        // Configure the scope
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("offline_access");
        options.Scope.Add("read:weather");

        // Set the callback path, so Auth0 will call back to http://localhost:3000/callback
        // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard
        options.CallbackPath = new PathString("/callback");

        // Configure the Claims Issuer to be Auth0
        options.ClaimsIssuer = "Auth0";

        // This saves the tokens in the session cookie
        options.SaveTokens = true;

        options.Events = new OpenIdConnectEvents
        {
            // handle the logout redirection
            OnRedirectToIdentityProviderForSignOut = (context) =>
            {
                var logoutUri = $"https://{config["Auth0:Domain"]}/v2/logout?client_id={config["Auth0:ClientId"]}";

                var postLogoutUri = context.Properties.RedirectUri;
                if (!string.IsNullOrEmpty(postLogoutUri))
                {
                    if (postLogoutUri.StartsWith("/"))
                    {
                        // transform to absolute
                        var request = context.Request;
                        postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                    }

                    logoutUri += $"&returnTo={Uri.EscapeDataString(postLogoutUri)}";
                }

                context.Response.Redirect(logoutUri);
                context.HandleResponse();

                return Task.CompletedTask;
            },
            OnRedirectToIdentityProvider = context =>
            {
                context.ProtocolMessage.SetParameter("audience", config["Auth0:ApiAudience"]);
                return Task.CompletedTask;
            }
        };
    }
}