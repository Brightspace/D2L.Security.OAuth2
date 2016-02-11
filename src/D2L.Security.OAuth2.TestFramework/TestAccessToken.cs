using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using IAccessToken = D2L.Security.OAuth2.Provisioning.IAccessToken;

namespace D2L.Security.OAuth2.TestFramework {

	/// <summary>
	/// Convienence class for tests to quickly get an auth token string
	/// </summary>
	public static class TestAccessToken {

		private const string DEFAULT_ISSUER = "ExpandoClient";

		/// <summary>
		/// Convienence method to get an auth token string.
		/// </summary>
		/// <param name="tokenProvisioningEndpoint">The auth server.</param>
		/// <param name="claimSet">The set of claims to be included in the token. Do not include an issuer.</param>
		/// <param name="scopes">The set of scopes to be included in the token.</param>
		/// <returns>An auth token string.</returns>
		public static async Task<string> GetToken( string tokenProvisioningEndpoint, IEnumerable<Claim> claimSet, IEnumerable<Scope> scopes ) {
			IList<Claim> claims = claimSet.ToList();
			if( claims.HasClaim( Constants.Claims.ISSUER ) ) {
				throw new ArgumentException( "The claimSet should not have an issuer" );
			}

			claims.Add( new Claim( Constants.Claims.ISSUER, DEFAULT_ISSUER ) );

			using( var httpClient = new HttpClient() ) {
				IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create( httpClient, tokenProvisioningEndpoint );
				IAccessToken token = await provider.ProvisionAccessTokenAsync( claims, scopes ).SafeAsync();
				return token.Token;
			}
		}

		/// <summary>
		/// Convienence method to get an auth token string.
		/// </summary>
		/// <param name="tokenProvisioningEndpoint">The auth server.</param>
		/// <param name="tenantId">The tenant id.</param>
		/// <param name="userId">The user id.</param>
		/// <param name="xsrfToken">The xsrf token.</param>
		/// <returns>An auth token string.</returns>
		public static async Task<string> GetToken( string tokenProvisioningEndpoint, string tenantId, string userId = null, string xsrfToken = null ) {
			IList<Claim> claimSet = new List<Claim>();
			if( tenantId != null ) {
				claimSet.Add( new Claim( Constants.Claims.TENANT_ID, tenantId ) );
			}
			if( userId != null ) {
				claimSet.Add( new Claim( Constants.Claims.USER_ID, userId ) );
			}
			if( xsrfToken != null ) {
				claimSet.Add( new Claim( Constants.Claims.XSRF_TOKEN, xsrfToken ) );
			}
			return await GetToken( tokenProvisioningEndpoint, claimSet, new[] { new Scope( "*", "*", "*" ) } ).SafeAsync();
		}

	}
}
