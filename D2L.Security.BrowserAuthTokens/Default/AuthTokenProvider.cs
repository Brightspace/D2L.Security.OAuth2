using System;
using System.Text;

namespace D2L.Security.BrowserAuthTokens.Default {
	public sealed class AuthTokenProvider : IAuthTokenProvider {
		public string GetTokenForUser( string tenantId, long userId, string xsrfToken, long duration ) {
			const string header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

			string payload = String.Format( "{{\"uid\":{0},\"tid\":\"{1}\",\"xt\":\"{2}\"}}", userId, tenantId, xsrfToken );

			return String.Format( "{0}.{1}.trustme", Base64Url(header), Base64Url(payload) );
		}

		private static string Base64Url( string s ) {
			return Base64Url( Encoding.UTF8.GetBytes( s ) );
		}

		private static string Base64Url( byte[] s ) {
			return Convert.ToBase64String( s )
						.Replace( '+', '-' )
						.Replace( '/', '_' )
						.Trim( '=' );
		}
	}
}