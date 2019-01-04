using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	internal sealed class JwksProvider : IJwksProvider {
		private readonly HttpClient m_httpClient;
		private readonly Uri m_authEndpoint;

		public JwksProvider(
			HttpClient httpClient,
			Uri authEndpoint
		) {
			m_httpClient = httpClient;
			m_authEndpoint = authEndpoint;
		}

		async Task<JsonWebKeySet> IJwksProvider.RequestJwksAsync() {
			var url = GetJwksEndpoint( m_authEndpoint );

			try {
				using( HttpResponseMessage response = await m_httpClient.GetAsync( url ).SafeAsync() ) {
					response.EnsureSuccessStatusCode();
					string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();
					var jwks = new JsonWebKeySet( jsonResponse, url );
					return jwks;
				}
			} catch( HttpRequestException e ) {
				throw CreateException( e, url );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e, url );
			}
		}

		async Task<JsonWebKeySet> IJwksProvider.RequestJwkAsync( Guid keyId ) {
			var url = GetJwkEndpoint( m_authEndpoint, keyId );
			try {
				using( var res = await m_httpClient.GetAsync( url ).SafeAsync() ) {
					if ( res.StatusCode == HttpStatusCode.NotFound ) {
						return JsonWebKeySet.Empty( url );
					}

					res.EnsureSuccessStatusCode();

					string json = await res.Content
						.ReadAsStringAsync()
						.SafeAsync();

					JsonWebKey jwk = JsonWebKey.FromJson( json );
					return new JsonWebKeySet( jwk, url );
				}
			} catch( HttpRequestException e ) {
				throw CreateException( e, url );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e, url );
			}
		}

		string IJwksProvider.Namespace => m_authEndpoint.AbsoluteUri;

		private Exception CreateException( Exception e, Uri endpoint ) {
			string message = $"Error while looking up key(s) at {endpoint}: {e.Message}";

			return new PublicKeyLookupFailureException( message, e );
		}

		private static Uri GetJwkEndpoint( Uri authEndpoint, Guid keyId ) {
			string authRoot = MakeSureThereIsATrailingSlash( authEndpoint );

			authRoot += $"jwk/{keyId}";

			return new Uri( authRoot );
		}

		private static Uri GetJwksEndpoint( Uri authEndpoint ) {
			string authRoot = MakeSureThereIsATrailingSlash( authEndpoint );

			authRoot += ".well-known/jwks";

			return new Uri( authRoot );
		}

		private static string MakeSureThereIsATrailingSlash( Uri uri ) {
			string root = uri.ToString();
			if( root[ root.Length - 1 ] == '/' ) {
				return root;
			}

			return root + '/';
		}
	}
}
