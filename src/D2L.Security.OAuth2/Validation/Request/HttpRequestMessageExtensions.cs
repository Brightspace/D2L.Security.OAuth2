using System.Net.Http;

namespace D2L.Security.OAuth2.Validation.Request {
	internal static class HttpRequestMessageExtensions {
		/// <param name="request">The request</param>
		/// <returns>The value of the bearer token, or null if the bearer token is not set</returns>
		internal static string? GetBearerTokenValue( this HttpRequestMessage request ) {
			var authHeader = request.Headers.Authorization;
			if( authHeader == null ) {
				return null;
			}

			if( authHeader.Scheme != RequestValidationConstants.BearerTokens.SCHEME ) {
				return null;
			}

			return authHeader.Parameter;
		}
	}
}
