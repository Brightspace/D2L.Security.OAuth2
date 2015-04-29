using System;
using System.Net.Http;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal sealed class JwksProvider : IJwksProvider {
		
		async Task<JwksResponse> IJwksProvider.RequestJwksAsync( Uri authEndpoint, bool skipCache ) {

			Uri jwksEndpoint = BuildJwksEndpoint( authEndpoint );

			// TODO: control httpclient creation?
			using( var httpClient = new HttpClient() ) {

				using( HttpResponseMessage response = await httpClient.GetAsync( authEndpoint ).SafeAsync() ) {
					try {
						response.EnsureSuccessStatusCode();
						string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();

						return new JwksResponse(
							fromCache: false,
							jwksJson: jsonResponse );

					} catch( Exception e ) {
						string message = string.Format( "Error while looking up JWKS at {0}", authEndpoint );
						throw new PublicKeyLookupFailureException( message, e );
					}
				}

			}
		}

		private static Uri BuildJwksEndpoint( Uri authEndpoint ) {
			string authRoot = authEndpoint.ToString();
			if( !authRoot.EndsWith( "/" ) ) {
				authRoot += "/";
			}

			authRoot += ".well-known/jwks";

			return new Uri( authRoot );
		}
	}
}
