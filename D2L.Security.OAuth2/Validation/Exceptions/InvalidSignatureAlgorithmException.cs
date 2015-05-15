using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that an invalid or unsupported signature algorithm was specified
	/// </summary>
	public class InvalidSignatureAlgorithmException : Exception {

		/// <summary>
		/// Constructs a new <see cref="InvalidSignatureAlgorithmException"/>
		/// </summary>
		public InvalidSignatureAlgorithmException( string message ) : base( message ) {}

	}
}
