using System.Linq;
using System.Net.Http;

namespace D2L.Security.RequestAuthentication {
	internal static class HttpRequestMessageExtensions {

		private const string COOKIE_HEADER = "Cookie";

		/// <summary>
		/// Return the value of a cookie
		/// </summary>
		/// <param name="request">The request from which the cookie value is extracted</param>
		/// <param name="cookieName">The name of the cookie</param>
		/// <returns>A cookie value, or null if the specified cookie was not found</returns>
		internal static string GetCookieValue( this HttpRequestMessage request, string cookieName ) {

			if( string.IsNullOrEmpty( cookieName ) ) {
				return null;
			}

			if( request == null || request.Headers == null ) {
				return null;
			}

			if( !request.Headers.Contains( COOKIE_HEADER ) ) {
				return null;
			}

			string allCookies = request.Headers.GetValues( COOKIE_HEADER ).FirstOrDefault();
			if( allCookies == null ) {
				return null;
			}

			string[] allCookiesArray = allCookies.Split( ';' );


			string cookieValue = null;
			var cookiePair = allCookiesArray.Select( c => c.Split( '=' ) ).FirstOrDefault( c => c[0] == cookieName );
			if( cookiePair != null ) {
				cookieValue = cookiePair[1];
			}

			return cookieValue;
		}
	}
}
