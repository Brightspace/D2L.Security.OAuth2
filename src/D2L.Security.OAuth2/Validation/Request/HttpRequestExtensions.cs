using System.Web;

namespace D2L.Security.OAuth2.Validation.Request {
	internal static class HttpRequestExtensions {

		/// <param name="request">The request</param>
		/// <returns>The value of the auth cookie, or null if one was not found</returns>
		internal static string GetCookieValue( this HttpRequest request ) {
			HttpCookie cookie = request.Cookies.Get( RequestValidationConstants.D2L_AUTH_COOKIE_NAME );
			if( cookie == null ) {
				return null;
			}

			return cookie.Value;
		}

		/// <param name="request">The request</param>
		/// <returns>The value of the bearer token, or null if the bearer token is not set</returns>
		internal static string GetBearerTokenValue( this HttpRequest request ) {
			string headerValue = request.Headers[RequestValidationConstants.Headers.AUTHORIZATION];
			if( headerValue == null ) {
				return null;
			}

			if( !headerValue.StartsWith( RequestValidationConstants.BearerTokens.SCHEME_PREFIX ) ) {
				return null;
			}

			string bearerToken = headerValue.Substring( RequestValidationConstants.BearerTokens.SCHEME_PREFIX.Length );
			return bearerToken;
		}

		/// <param name="request">The request</param>
		/// <returns>The value of the Xsrf header, or null if the Xsrf header was not found</returns>
		internal static string GetXsrfValue( this HttpRequest request ) {
			return request.Headers[RequestValidationConstants.Headers.XSRF];
		}
	}
}
