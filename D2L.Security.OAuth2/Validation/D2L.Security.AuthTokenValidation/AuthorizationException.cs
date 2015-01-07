using System;

namespace D2L.Security.AuthTokenValidation {

	public sealed class AuthorizationException : Exception {

		public AuthorizationException() {}
		public AuthorizationException( string message ) : base( message ) {}
		public AuthorizationException( string message, Exception inner ) : base( message, inner ) {}
	}
}
