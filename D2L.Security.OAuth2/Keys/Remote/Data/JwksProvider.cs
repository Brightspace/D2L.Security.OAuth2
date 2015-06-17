using System;
using System.Net.Http;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal sealed class JwksProvider : IJwksProvider {
		
		async Task<JwksResponse> IJwksProvider.RequestJwksAsync( Uri authEndpoint, bool skipCache ) {

			Uri jwksEndpoint = BuildJwksEndpoint( authEndpoint );

			// TODO: we should be taking httpClients from users at the top of the stack so they
			// can control things like proxy settings.
			using( var httpClient = new HttpClient() ) {
				try {
					using( HttpResponseMessage response = await httpClient.GetAsync( jwksEndpoint ).SafeAsync() ) {
						response.EnsureSuccessStatusCode();
						string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();

						return new JwksResponse(
							fromCache: false,
							jwksJson: jsonResponse );
					}
				} catch( HttpRequestException e ) {
					string message = string.Format(
						"Error while looking up JWKS at {0}: {1}",
						jwksEndpoint,
						e.Message );
					throw new PublicKeyLookupFailureException( message, e );
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
