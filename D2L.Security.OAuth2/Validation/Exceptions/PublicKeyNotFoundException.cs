using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the public key could not be found
	/// </summary>
	public class PublicKeyNotFoundException : Exception {

		/// <summary>
		/// Constructs a new <see cref="PublicKeyNotFoundException"/>
		/// </summary>
		public PublicKeyNotFoundException( string message ) : base( message ) {}

	}
}
