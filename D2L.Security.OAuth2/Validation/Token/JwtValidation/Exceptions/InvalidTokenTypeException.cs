using System;

namespace D2L.Security.OAuth2.Validation.Token.JwtValidation.Exceptions {
	internal sealed class InvalidTokenTypeException : Exception {
		internal InvalidTokenTypeException( string message ) : base( message ) { }
	}
}
