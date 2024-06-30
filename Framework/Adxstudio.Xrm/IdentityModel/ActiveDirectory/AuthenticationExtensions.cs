/*
  Copyright (c) Microsoft Corporation. All rights reserved.
  Licensed under the MIT License. See License.txt in the project root for license information.
*/


namespace Adxstudio.Xrm.IdentityModel.ActiveDirectory
{
	using System;
	using System.Security.Cryptography.X509Certificates;
	using System.Threading.Tasks;
    using Adxstudio.Xrm.Configuration;
    //using Microsoft.IdentityModel.Clients.ActiveDirectory;
	using Microsoft.Identity.Client;
    using Microsoft.IdentityModel.Tokens;

    //using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Helpers related to token management.
    /// </summary>
    public static class AuthenticationExtensions
	{
		/// <summary>
		/// Retrieves a token from the certificate.
		/// </summary>
		/// <param name="certificate">The certificate.</param>
		/// <param name="authenticationSettings">The authentication settings.</param>
		/// <param name="resource">The target resource.</param>
		/// <returns>The token.</returns>
		public static async Task<AuthenticationResult> GetTokenAsync(this X509Certificate2 certificate, IAuthenticationSettings authenticationSettings, string resource)
		{
			return await GetTokenOnBehalfOfAsync(certificate, authenticationSettings, resource, string.Empty);

            //var authenticationContext = GetAuthenticationContext(authenticationSettings);

            // Then create the certificate credential.
            //var application = ConfidentialClientApplicationBuilder.Create(authenticationSettings.ClientId);
            //         var certificateCredential = application.WithCertificate(certificate);
            //var certificateCredential = ClientAssertionCertificate(authenticationSettings.ClientId, certificate);

            //// ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
            //var authResult = await authenticationContext.AcquireTokenAsync(resource, certificateCredential);

            //return authResult;
        }

        /// <summary>
        /// Retrieves a token from the certificate for delegated auth
        /// </summary>
        /// <param name="certificate">The application's certificate</param>
        /// <param name="authenticationSettings">Authentication settings</param>
        /// <param name="resource">Requested resource</param>
        /// <param name="authorizationCode">Access code for user assertion</param>
        /// <returns>Authentication result including token</returns>
        public static async Task<AuthenticationResult> GetTokenOnBehalfOfAsync(this X509Certificate2 certificate, IAuthenticationSettings authenticationSettings, string resource, string authorizationCode)
		{
            //	var authenticationContext = GetAuthenticationContext(authenticationSettings);

            //	// Then create the certificate credential and user assertion.
            //	var certificateCredential = new ClientAssertionCertificate(authenticationSettings.ClientId, certificate);

            //	// ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
            //	var authResult = await authenticationContext.AcquireTokenByAuthorizationCodeAsync(
            //		authorizationCode,
            //		new Uri(authenticationSettings.RedirectUri),
            //		certificateCredential,
            //		resource);

            //	return authResult;

            //https://learn.microsoft.com/en-us/entra/msal/dotnet/how-to/migrate-confidential-client?tabs=daemon
            string authority = $"https://login.microsoftonline.com/{authenticationSettings.TenantId}";

			// App ID URI of web API to call
			//const string resourceId = "https://target-api.domain.com";

			var app = ConfidentialClientApplicationBuilder.Create(authenticationSettings.ClientId)
				.WithCertificate(certificate)
				.WithAuthority(authority)
				.Build();

			// Setup token caching https://learn.microsoft.com/azure/active-directory/develop/msal-net-token-cache-serialization?tabs=aspnet
			// For example, for an in-memory cache with 1GB limit, use  
			//app.AddInMemoryTokenCache(services =>
			//{
			//	// Configure the memory cache options
			//	services.Configure<MemoryCacheOptions>(options =>
			//	{
			//		options.SizeLimit = 1024 * 1024 * 1024; // in bytes (1 GB of memory)
			//	});
			//});

			var authResult = await app.AcquireTokenForClient(
			new[] { $"{resource}/.default" })
			// .WithTenantId(specificTenant)
			// See https://aka.ms/msal.net/withTenantId
			.ExecuteAsync()
			.ConfigureAwait(false);

			return authResult;
		}

				/// <summary>
		/// Retrieves a token from the certificate.
		/// </summary>
		/// <param name="certificate">The certificate.</param>
		/// <param name="authenticationSettings">The authentication settings.</param>
		/// <param name="resource">The target resource.</param>
		/// <returns>The token.</returns>
		public static AuthenticationResult GetToken(this X509Certificate2 certificate, IAuthenticationSettings authenticationSettings, string resource)
		{
            return GetTokenOnBehalfOfAsync(certificate, authenticationSettings, resource, string.Empty).Result;

            //var authenticationContext = GetAuthenticationContext(authenticationSettings);

            //// Then create the certificate credential.
            //var certificateCredential = new ClientAssertionCertificate(authenticationSettings.ClientId, certificate);

            //// ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
            //var authResult = authenticationContext.AcquireTokenAsync(resource, certificateCredential).Result;

            //return authResult;
        }

        /// <summary>
        /// Retrieves a token from the certificate for delegated auth
        /// </summary>
        /// <param name="certificate">The application's certificate</param>
        /// <param name="authenticationSettings">Authentication settings</param>
        /// <param name="resource">Requested resource</param>
        /// <param name="authorizationCode">Access code for user assertion</param>
        /// <returns>Authentication result including token</returns>
        public static AuthenticationResult GetTokenOnBehalfOf(this X509Certificate2 certificate, IAuthenticationSettings authenticationSettings, string resource, string authorizationCode)
		{
            return GetTokenOnBehalfOfAsync(certificate, authenticationSettings, resource, authorizationCode).Result;
            //var authenticationContext = GetAuthenticationContext(authenticationSettings);

            //// Then create the certificate credential and user assertion.
            //var certificateCredential = new ClientAssertionCertificate(authenticationSettings.ClientId, certificate);

            //// ADAL includes an in memory cache, so this call will only send a message to the server if the cached token is expired.
            //var authResult = authenticationContext.AcquireTokenByAuthorizationCodeAsync(
            //	authorizationCode,
            //	new Uri(authenticationSettings.RedirectUri),
            //	certificateCredential,
            //	resource).Result;

            //return authResult;
        }

		/// <summary>
		/// Creates an authentication context.
		/// </summary>
		/// <param name="authenticationSettings">The authentication settings.</param>
		/// <returns>The context.</returns>
//		private static AuthenticationContext GetAuthenticationContext(IAuthenticationSettings authenticationSettings)
//		{
//			return new AuthenticationContext(string.Format("{0}/{1}", authenticationSettings.RootUrl, authenticationSettings.TenantId));
//            var app = ConfidentialClientApplicationBuilder.Create(ClientId)
//.WithCertificate(certificate)
//.WithAuthority(authority)
//.Build();
//        }
	}
}
