using System.Linq;
using System.Net.Http;

namespace D2L.Security.RequestAuthentication {
	internal static class HttpRequestMessageExtensions {

		private const string COOKIE_HEADER = "Cookie";
		private const string XSRF_HEADER = "X-Csrf-Token";

		/// <summary>
		/// Return the value of a cookie
		/// </summary>
		/// <param name="request">The request</param>
		/// <param name="cookieName">The name of the cookie</param>
		/// <returns>A cookie value, or null if the specified cookie was not found</returns>
		internal static string GetCookieValue( this HttpRequestMessage request, string cookieName ) {
			string cookiesHeaderValue = request.GetHeaderValue( COOKIE_HEADER );
			if( cookiesHeaderValue == null ) {
				return null;
			}

			if( string.IsNullOrEmpty( cookieName ) ) {
				return null;
			}

			string[] allCookiesArray = cookiesHeaderValue.Split( ';' );


			string cookieValue = null;
			var cookiePair = allCookiesArray.Select( c => c.Split( '=' ) ).FirstOrDefault( c => c[0] == cookieName );
			if( cookiePair != null ) {
				cookieValue = cookiePair[1];
			}

			return cookieValue;
		}

		/// <summary>
		/// Returns the value of the Xsrf header.
		/// </summary>
		/// <param name="request">The request</param>
		/// <returns>The value of the Xsrf header, or null if the Xsrf header was not found</returns>
		internal static string GetXsrfValue( this HttpRequestMessage request ) {
			return request.GetHeaderValue( XSRF_HEADER );
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
