using System;
using System.Net.Http;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Validation.Jwks.Data {
	internal sealed class JwksProvider : IJwksProvider {
		
		async Task<JwksResponse> IJwksProvider.RequestJwksAsync( Uri endpoint, bool skipCache ) {

			// TODO: control httpclient creation?
			using( var httpClient = new HttpClient() ) {

				using( HttpResponseMessage response = await httpClient.GetAsync( endpoint ).SafeAsync() ) {
					try {
						response.EnsureSuccessStatusCode();
						string jsonResponse = await response.Content.ReadAsStringAsync().SafeAsync();

						return new JwksResponse(
							fromCache: false,
							jwksJson: jsonResponse );

					} catch( Exception e ) {
						string message = string.Format( "Error while looking up JWKS at {0}", endpoint );
						throw new PublicKeyLookupFailureException( message, e );
					}
				}

			}
		}
	}
}
