using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the public key lookup failed
	/// </summary>
	public sealed class PublicKeyLookupFailureException : ValidationException {

		/// <summary>
		/// Constructs a new <see cref="PublicKeyLookupFailureException"/>
		/// </summary>
		public PublicKeyLookupFailureException( string message, Exception inner )
			: base( message, inner ) {}
	}
}
