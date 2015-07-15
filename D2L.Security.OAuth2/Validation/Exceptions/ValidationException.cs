using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Base class for exceptions during validation
	/// </summary>
	public class ValidationException : Exception {
		internal ValidationException( string message ) : base( message ) {}
		internal ValidationException( string message, Exception inner ) : base( message, inner ) {}
	}
}
