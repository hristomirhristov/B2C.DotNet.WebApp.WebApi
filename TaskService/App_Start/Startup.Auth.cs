using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Configuration;
using TaskService.App_Start;

namespace TaskService
{
    public partial class Startup
    {
        // These values are pulled from web.config
        public static string AadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string SignUpSignInPolicy = ConfigurationManager.AppSettings["ida:SignUpSignInPolicyId"];
        public static string DefaultPolicy = SignUpSignInPolicy;

        public static string AadInstanceAutoTest = ConfigurationManager.AppSettings["ida:AadInstanceAutoTest"];
        public static string TenantAutoTest = ConfigurationManager.AppSettings["ida:TenantAutoTest"];
        public static string ClientIdAutoTest = ConfigurationManager.AppSettings["ida:ClientIdAutoTest"];
        public static string SignUpSignInPolicyAutoTest = ConfigurationManager.AppSettings["ida:SignUpSignInPolicyIdAutoTest"];

        public const string ClaimName = "emails";

        /*
         * Configure the authorization OWIN middleware 
         */
        public void ConfigureAuth(IAppBuilder app)
        {
            TokenValidationParameters tvps = new TokenValidationParameters
            {
                // Accept only those tokens where the audience of the token is equal to the client ID of this app
                ValidAudience = ClientId,
                AuthenticationType = Startup.DefaultPolicy
            };

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(tvps, new OpenIdConnectCachingSecurityTokenProvider(String.Format(AadInstance, Tenant, DefaultPolicy)))
            });

            #region Extends MS template. Validates Password grant tokens!
            if (!string.IsNullOrWhiteSpace(SignUpSignInPolicyAutoTest))
            {
                TokenValidationParameters tvpsAutoTest = new TokenValidationParameters
                {
                    ValidAudience = ClientIdAutoTest,
                    AuthenticationType = SignUpSignInPolicyAutoTest
                };

                app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
                {
                    AccessTokenFormat = new JwtFormat(
                        tvpsAutoTest,
                        new OpenIdConnectCachingSecurityTokenProvider(string.Format(AadInstanceAutoTest, TenantAutoTest, SignUpSignInPolicyAutoTest)))
                });
            }
            #endregion
        }
    }
}
