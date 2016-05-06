using System;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	internal sealed class JwksProvider : IJwksProvider {

		private const string JWKS_PATH = ".well-known/jwks";

		private readonly HttpClient m_httpClient;
		private readonly Uri m_jwksEndpoint;

		public JwksProvider(
			HttpClient httpClient,
			Uri authEndpoint
		) {
			m_httpClient = httpClient;
			m_jwksEndpoint = BuildJwksEndpoint( authEndpoint );
		}
		
		async Task<JsonWebKeySet> IJwksProvider.RequestJwksAsync() {
			try {
				using( HttpResponseMessage response = await m_httpClient.GetAsync( m_jwksEndpoint ).SafeAsync() ) {
					response.EnsureSuccessStatusCode();
					string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();
					var jwks = new JsonWebKeySet( jsonResponse, m_jwksEndpoint );
					return jwks;
				}
			} catch( HttpRequestException e ) {
				throw CreateException( e );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e );
			}
		}

		private Exception CreateException( Exception e ) {
			string message = string.Format(
				"Error while looking up JWKS at {0}: {1}",
				m_jwksEndpoint,
				e.Message
			);

			return new PublicKeyLookupFailureException( message, e );
		}

		private static Uri BuildJwksEndpoint( Uri authEndpoint ) {
			string authRoot = authEndpoint.ToString();
			if( !authRoot.EndsWith( "/" ) ) {
				authRoot += "/";
			}

			authRoot += JWKS_PATH;

			return new Uri( authRoot );
		}
	}
}
