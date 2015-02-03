using System.Web;

namespace D2L.Security.RequestAuthentication {
	internal static class HttpRequestExtensions {

		/// <param name="request">The request</param>
		/// <returns>The value of the auth cookie, or null if one was not found</returns>
		internal static string GetCookieValue( this HttpRequest request ) {
			if( request == null ) {
				return null;
			}

			HttpCookie cookie = request.Cookies.Get( Constants.D2L_AUTH_COOKIE_NAME );
			if( cookie == null ) {
				return null;
			}

			return cookie.Value;
		}

		/// <param name="request">The request</param>
		/// <returns>The value of the bearer token, or null if the bearer token is not set</returns>
		internal static string GetBearerTokenValue( this HttpRequest request ) {
			if( request == null ) {
				return null;
			}

			string headerValue = request.Headers[Constants.Headers.AUTHORIZATION];
			if( headerValue == null ) {
				return null;
			}

			if( !headerValue.StartsWith( Constants.BearerTokens.SCHEME_PREFIX ) ) {
				return null;
			}

			string bearerToken = headerValue.Substring( Constants.BearerTokens.SCHEME_PREFIX.Length );
			return bearerToken;
		}

		/// <param name="request">The request</param>
		/// <returns>The value of the Xsrf header, or null if the Xsrf header was not found</returns>
		internal static string GetXsrfValue( this HttpRequest request ) {
			if( request == null ) {
				return null;
			}

			string xsrfValue = request.Headers[Constants.Headers.XSRF];
			return xsrfValue;
		}
	}
}
