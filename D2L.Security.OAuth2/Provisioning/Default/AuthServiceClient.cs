using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {

	/// <summary>
	/// Calls the Auth Service to provision access tokens
	/// </summary>
	/// <remarks>This type is disposable</remarks>
	public sealed class AuthServiceClient : IAuthServiceClient {

		private readonly HttpClient m_client;
		private readonly bool m_disposeClient;
		private readonly Uri m_tokenProvisioningEndpoint;

		/// <summary>
		/// Constructs a new <see cref="AuthServiceClient"/>
		/// </summary>
		/// <param name="tokenProvisioningEndpoint">The token provisioning endpoint on the auth service</param>
		public AuthServiceClient(
			Uri tokenProvisioningEndpoint
		)
			: this(
			  httpClient: new HttpClient(),
			  tokenProvisioningEndpoint: tokenProvisioningEndpoint
			) { }

		/// <summary>
		/// Constructs a new <see cref="AuthServiceClient"/>
		/// </summary>
		/// <param name="httpClient">An http client used to communicate with the auth service.</param>
		/// <param name="tokenProvisioningEndpoint">The token provisioning endpoint on the auth service</param>
		/// <param name="disposeHttpClient">If true, <paramref name="httpClient"/> will be disposed of</param>
		public AuthServiceClient(
			HttpClient httpClient,
			Uri tokenProvisioningEndpoint,
			bool disposeHttpClient = true
		) {
			m_client = httpClient;
			m_disposeClient = disposeHttpClient;
			m_tokenProvisioningEndpoint = tokenProvisioningEndpoint;
		}

		/// <summary>
		/// Provisions an access token from the auth service
		/// </summary>
		/// <param name="assertion">A JWT signed by the private key of the entity requesting the token</param>
		/// <param name="scopes">List of scopes to include in the access token</param>
		/// <returns>A JWT token from the auth service signed with the auth service's private key</returns>
		async Task<IAccessToken> IAuthServiceClient.ProvisionAccessTokenAsync(
			string assertion,
			IEnumerable<Scope> scopes
		) {
			string requestBody = BuildFormContents( assertion, scopes );
			using( HttpResponseMessage response = await MakeRequest( requestBody ).SafeAsync() ) {
				response.EnsureSuccessStatusCode();

				using( var resultStream = await response.Content.ReadAsStreamAsync().SafeAsync() ) {
					IAccessToken accessToken = SerializationHelper.ExtractAccessToken( resultStream );
					return accessToken;
				}
			}
		}

		/// <summary>
		/// Disposes the <see cref="AuthServiceClient"/>
		/// </summary>
		public void Dispose() {
			if( m_disposeClient ) {
				m_client.Dispose();
			}
		}

		private Task<HttpResponseMessage> MakeRequest( string body ) {
			var request = new HttpRequestMessage( HttpMethod.Post, m_tokenProvisioningEndpoint );
			request.Content = new StringContent( body, Encoding.UTF8, "application/x-www-form-urlencoded" );

			return m_client.SendAsync( request );
		}

		private static string BuildFormContents( string assertion, IEnumerable<Scope> scopes ) {
			StringBuilder builder = new StringBuilder( "grant_type=" );
			builder.Append( ProvisioningConstants.AssertionGrant.GRANT_TYPE );

			builder.Append( "&assertion=" );
			builder.Append( assertion );

			var scopesString = String.Join( " ", scopes );
			scopesString = WebUtility.UrlEncode( scopesString );
			builder.Append( "&scope=" );
			builder.Append( scopesString );

			var result = builder.ToString();
			return result;
		}
	}
}
