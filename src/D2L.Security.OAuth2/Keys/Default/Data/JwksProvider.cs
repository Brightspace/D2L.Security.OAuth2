using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Utilities;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default.Data {
	internal sealed partial class JwksProvider : IJwksProvider {
		private readonly D2LHttpClient m_httpClient;
		private readonly Uri m_jwksEndpoint;
		private readonly Uri m_jwkEndpoint;

		public JwksProvider(
			D2LHttpClient httpClient,
			Uri jwksEndpoint,
			Uri jwkEndpoint
		) {
			m_httpClient = httpClient;
			m_jwksEndpoint = jwksEndpoint;
			m_jwkEndpoint = jwkEndpoint;
		}

		[GenerateSync]
		async Task<JsonWebKeySet> IJwksProvider.RequestJwksAsync() {
			try {
				using( HttpResponseMessage response = await m_httpClient.GetAsync( m_jwksEndpoint ).ConfigureAwait( false ) ) {
					response.EnsureSuccessStatusCode();
					using var reader = new StreamReader(await response.Content.ReadAsStreamAsync().ConfigureAwait(false));
					string jsonResponse = await reader
						.ReadToEndAsync()
						.ConfigureAwait(false);
					var jwks = new JsonWebKeySet( jsonResponse, m_jwksEndpoint );
					return jwks;
				}
			} catch( HttpRequestException e ) {
				throw CreateException( e, m_jwksEndpoint );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e, m_jwksEndpoint );
			}
		}

		[GenerateSync]
		async Task<JsonWebKeySet> IJwksProvider.RequestJwkAsync( string keyId ) {
			var url = GetJwkEndpoint( m_jwkEndpoint, keyId );
			if( url == null ) {
				return await ( this as IJwksProvider ).RequestJwksAsync().ConfigureAwait( false );
			}

			try {
				using( var res = await m_httpClient.GetAsync( url ).ConfigureAwait( false ) ) {
					// This is temporary while we try to fully deprecate the
					// JWKS route. 404 might mean the key doesn't exist (which
					// will make the call to jwks likely return 200 but still
					// result in no key - that's fine but slow) or the jwk
					// route isn't supported which will make this recover (but
					// slowely.) Where it matters (the LMS and auth) JWK is
					// supported so this shouldn't be necessary. We don't
					// expect many "legitimate" 404s (keys that don't exist.)
					// so in practice this should only happen when it's
					// actually important, if it ever happens.
					if( res.StatusCode != HttpStatusCode.OK ) {
						return await ( this as IJwksProvider ).RequestJwksAsync().ConfigureAwait( false );
					}

					res.EnsureSuccessStatusCode();

					using var reader = new StreamReader(await res.Content.ReadAsStreamAsync().ConfigureAwait(false));
					string json = await reader
						.ReadToEndAsync()
						.ConfigureAwait(false);

					JsonWebKey jwk = JsonWebKey.FromJson( json );
					return new JsonWebKeySet( jwk, url );
				}
			} catch( HttpRequestException e ) {
				throw CreateException( e, url );
			} catch( JsonWebKeyParseException e ) {
				throw CreateException( e, url );
			}
		}

		string IJwksProvider.Namespace => m_jwksEndpoint.AbsoluteUri;

		private Exception CreateException( Exception e, Uri endpoint ) {
			string message = $"Error while looking up key(s) at {endpoint}: {e.Message}";

			return new PublicKeyLookupFailureException( message, e );
		}

		private static Uri GetJwkEndpoint( Uri authEndpoint, string keyId ) {
			if( authEndpoint == null ) { return null; }

			return authEndpoint.RelativePathAsNonLeaf( HttpUtility.UrlEncode( keyId ) );
		}
	}
}
