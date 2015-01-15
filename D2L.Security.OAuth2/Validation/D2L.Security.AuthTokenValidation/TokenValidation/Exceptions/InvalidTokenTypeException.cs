using System;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Exceptions {
	internal sealed class InvalidTokenTypeException : Exception {
		internal InvalidTokenTypeException( string message ) : base( message ) { }
	}
}
