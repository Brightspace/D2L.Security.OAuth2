using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that an invalid or unsupported key type was specified
	/// </summary>
	public class InvalidKeyTypeException : Exception {

		/// <summary>
		/// Constructs a new <see cref="InvalidKeyTypeException"/>
		/// </summary>
		public InvalidKeyTypeException( string message ) : base( message ) {}

	}
}
