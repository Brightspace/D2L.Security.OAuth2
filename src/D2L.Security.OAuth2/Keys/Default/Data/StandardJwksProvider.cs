using System;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	class StandardJwksProvider : IJwksProvider {
		private readonly HttpClient m_httpClient;
		private readonly Uri m_authEndpoint;

		public StandardJwksProvider(
			HttpClient httpClient,
			Uri authEndpoint
		) {
			m_httpClient = httpClient;
			m_authEndpoint = authEndpoint;
		}

		string IJwksProvider.Namespace => m_authEndpoint.AbsoluteUri;

		async Task<JsonWebKeySet> IJwksProvider.RequestJwkAsync( string keyId ) {
			try {
				return await ( this as IJwksProvider ).RequestJwksAsync().SafeAsync();
			} catch( HttpRequestException e ) {
				throw CreateException( e, m_authEndpoint );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e, m_authEndpoint );
			}
		}

		async Task<JsonWebKeySet> IJwksProvider.RequestJwksAsync() {
			try {
				using( HttpResponseMessage response = await m_httpClient.GetAsync( m_authEndpoint ).SafeAsync() ) {
					response.EnsureSuccessStatusCode();
					string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();
					var jwks = new JsonWebKeySet( jsonResponse, m_authEndpoint );
					return jwks;
				}
			} catch( HttpRequestException e ) {
				throw CreateException( e, m_authEndpoint );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e, m_authEndpoint );
			}
		}

		private Exception CreateException( Exception e, Uri endpoint ) {
			string message = $"Error while looking up key(s) at {endpoint}: {e.Message}";

			return new PublicKeyLookupFailureException( message, e );
		}
	}
}
