#if !DNXCORE50

using System.Web;

namespace D2L.Security.OAuth2.Validation.Request {
	internal static class HttpRequestExtensions {
		/// <param name="request">The request</param>
		/// <returns>The value of the bearer token, or null if the bearer token is not set</returns>
		internal static string GetBearerTokenValue( this HttpRequest request ) {
			string headerValue = request.Headers[ RequestValidationConstants.Headers.AUTHORIZATION ];
			if( headerValue == null ) {
				return null;
			}

			if( !headerValue.StartsWith( RequestValidationConstants.BearerTokens.SCHEME_PREFIX ) ) {
				return null;
			}

			string bearerToken = headerValue.Substring( RequestValidationConstants.BearerTokens.SCHEME_PREFIX.Length );
			return bearerToken;
		}
	}
}

#endif
