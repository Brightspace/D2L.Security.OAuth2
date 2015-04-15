using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {
	public class InvalidSignatureAlgorithmException : Exception {

		public InvalidSignatureAlgorithmException( string message ) : base( message ) {}

	}
}
