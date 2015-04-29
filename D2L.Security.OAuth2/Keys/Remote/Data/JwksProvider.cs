using System;
using System.Net.Http;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal sealed class JwksProvider : IJwksProvider {
		
		async Task<JwksResponse> IJwksProvider.RequestJwksAsync( Uri authServiceEndpoint, bool skipCache ) {

			Uri jwksEndpoint = BuildJwksEndpoint( authServiceEndpoint );

			// TODO: control httpclient creation?
			using( var httpClient = new HttpClient() ) {

				using( HttpResponseMessage response = await httpClient.GetAsync( authServiceEndpoint ).SafeAsync() ) {
					try {
						response.EnsureSuccessStatusCode();
						string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();

						return new JwksResponse(
							fromCache: false,
							jwksJson: jsonResponse );

					} catch( Exception e ) {
						string message = string.Format( "Error while looking up JWKS at {0}", authServiceEndpoint );
						throw new PublicKeyLookupFailureException( message, e );
					}
				}

			}
		}

		private static Uri BuildJwksEndpoint( Uri authServiceEndpoint ) {
			string authRoot = authServiceEndpoint.ToString();
			if( !authRoot.EndsWith( "/" ) ) {
				authRoot += "/";
			}

			Uri authRootUri = new Uri( authRoot );
			Uri jwksEndpoint = new Uri( authRootUri, ".well-known/jwks" );

			return jwksEndpoint;
		}
	}
}
