using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

namespace D2L.Security.RequestAuthentication {
	internal static class HttpRequestMessageExtensions {

		/// <summary>
		/// Return the value of a cookie
		/// </summary>
		/// <param name="request">The request</param>
		/// <param name="cookieName">The name of the cookie</param>
		/// <returns>A cookie value, or null if the specified cookie was not found</returns>
		internal static string GetCookieValue( this HttpRequestMessage request, string cookieName ) {
			if( string.IsNullOrEmpty( cookieName ) ) {
				return null;
			}

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

				if( nameValuePair[0].Trim() == cookieName ) {
					return nameValuePair[1].Trim();
				}
			}

			return null;
		}

		/// <summary>
		/// Returns the value of the Xsrf header.
		/// </summary>
		/// <param name="request">The request</param>
		/// <returns>The value of the Xsrf header, or null if the Xsrf header was not found</returns>
		internal static string GetXsrfValue( this HttpRequestMessage request ) {
			string xsrfValue = request.GetHeaderValue( Constants.Headers.XSRF );
			return xsrfValue;
		}

		/// <summary>
		/// Returns the value of the bearer token.
		/// </summary>
		/// <param name="request">The request</param>
		/// <returns>The value of the bearer token, or null if the bearer token is not set</returns>
		internal static string GetBearerTokenValue( this HttpRequestMessage request ) {
			if( request == null ) {
				return null;
			}

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
			if( request == null || request.Headers == null ) {
				return null;
			}

			if( !request.Headers.Contains( headerName ) ) {
				return null;
			}

			string headerValue = request.Headers.GetValues( headerName ).FirstOrDefault();
			return headerValue;
		}
	}
}
