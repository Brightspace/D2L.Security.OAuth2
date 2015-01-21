using System;

namespace D2L.Security.AuthTokenValidation {

	/// <summary>
	/// Indicates a failure due to a token being expired
	/// </summary>
	public sealed class TokenExpiredException : Exception {

		public TokenExpiredException() {}
		public TokenExpiredException( string message ) : base( message ) { }
		public TokenExpiredException( string message, Exception inner ) : base( message, inner ) { }
	}
}
