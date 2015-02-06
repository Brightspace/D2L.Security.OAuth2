using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

namespace D2L.Security.RequestAuthentication {
	internal static class HttpRequestMessageExtensions {

		/// <param name="request">The request</param>
		/// <returns>The value of the auth cookie, or null if one was not found</returns>
		internal static string GetCookieValue( this HttpRequestMessage request ) {
			string cookiesHeaderValue = request.GetHeaderValue( Constants.Headers.COOKIE );
			if( cookiesHeaderValue == null ) {
				return null;
			}

			string[] allCookiesArray = cookiesHeaderValue.Split( ';' );
			foreach( string cookie in allCookiesArray ) {
				string[] nameValuePair = cookie.Split( '=' );
				if( nameValuePair.Length != 2 ) {
					continue;
				}

				if( nameValuePair[0].Trim() == Constants.D2L_AUTH_COOKIE_NAME ) {
					return nameValuePair[1].Trim();
				}
			}

			return null;
		}

		/// <param name="request">The request</param>
		/// <returns>The value of the Xsrf header, or null if the Xsrf header was not found</returns>
		internal static string GetXsrfValue( this HttpRequestMessage request ) {
			return request.GetHeaderValue( Constants.Headers.XSRF );
		}

		/// <param name="request">The request</param>
		/// <returns>The value of the bearer token, or null if the bearer token is not set</returns>
		internal static string GetBearerTokenValue( this HttpRequestMessage request ) {
			AuthenticationHeaderValue authHeader = request.Headers.Authorization;
			if( authHeader == null ) {
				return null;
			}

			if( authHeader.Scheme != Constants.BearerTokens.SCHEME ) {
				return null;
			}

			return authHeader.Parameter;
		}

		private static string GetHeaderValue( this HttpRequestMessage request, string headerName ) {
			if( !request.Headers.Contains( headerName ) ) {
				return null;
			}

			string headerValue = request.Headers.GetValues( headerName ).FirstOrDefault();
			return headerValue;
		}
	}
}
