using System;

namespace D2L.Security.AuthTokenValidation {

	/// <summary>
	/// A generic authorization exception
	/// </summary>
	public sealed class AuthorizationException : Exception {

		public AuthorizationException() { }
		public AuthorizationException( string message ) : base( message ) { }
		public AuthorizationException( string message, Exception inner ) : base( message, inner ) { }
	}
}
