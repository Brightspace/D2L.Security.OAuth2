using System;
using System.Text;

namespace D2L.Security.BrowserAuthTokens.Default {
	public sealed class AuthTokenProvider : IAuthTokenProvider {

		private const string JWT_HEADER = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
		
		private readonly TimeSpan ASSERTION_GRANT_JWT_LIFETIME = TimeSpan.FromMinutes( 30 );
		private readonly TimeSpan NOT_BEFORE_PADDING = TimeSpan.FromMinutes( 5 );

		/*
		grant_type    urn:ietf:params:oauth:grant-type:jwt-bearer
		assertion    (signed assertion grant JWT)
		scope     just like for client
		*/

		string IAuthTokenProvider.GetTokenForUser( string tenantId, long userId, string xsrfToken, long duration ) {
			throw new NotImplementedException();
		}

		//string IAuthTokenProvider.GetTokenForUser( string tenantId, long userId, string xsrfToken, long duration ) {
			
		//	StringBuilder builder = new StringBuilder();
		//	builder.Append( "{" );

		//	builder.Append( "}" );
		//	string payload = String.Format( "{{\"uid\":{0},\"tid\":\"{1}\",\"xt\":\"{2}\"}}", userId, tenantId, xsrfToken );

		//	return String.Format( "{0}.{1}.trustme", Base64Url(JWT_HEADER), Base64Url(payload) );
		//}

		//private void WriteTenantId( StringBuilder builder, string tenantId ) {
		//	builder.Append( "\"tenantid\":\"" );
		//	builder.Append( tenantId );
		//	builder.Append( "\"" );
		//}

		//private void WriteUserId( StringBuilder builder, long userId ) {
		//	builder.Append( "\"sub\":" );
		//	builder.Append( userId );
		//}

		//private void WriteExpiry( StringBuilder builder, DateTime now ) {
		//	DateTime expiry = now + ASSERTION_GRANT_JWT_LIFETIME;

		//	builder.Append( "\"exp\":" );
		//	builder.Append( expiry.GetSecondsSinceUnixEpoch() );
		//}

		//private void WriteNotBefore( StringBuilder builder, DateTime now ) {
		//	DateTime notBefore = now - NOT_BEFORE_PADDING;

		//	builder.Append( "\"nbf\":" );
		//	builder.Append( notBefore.GetSecondsSinceUnixEpoch() );
		//}

		//private void WriteComma( StringBuilder builder ) {
		//	builder.Append( ',' );
		//}


		//private static string Base64Url( string s ) {
		//	return Base64Url( Encoding.UTF8.GetBytes( s ) );
		//}

		//private static string Base64Url( byte[] s ) {
		//	return Convert.ToBase64String( s )
		//		.Replace( '+', '-' )
		//		.Replace( '/', '_' )
		//		.Trim( '=' );
		//}
	}
}