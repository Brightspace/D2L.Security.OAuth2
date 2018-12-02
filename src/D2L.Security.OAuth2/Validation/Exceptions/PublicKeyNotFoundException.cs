using System;
namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the public key could not be found
	/// </summary>
	public sealed class PublicKeyNotFoundException : ValidationException {

		/// <summary>
		/// Constructs a new <see cref="PublicKeyNotFoundException"/>
		/// </summary>
		[Obsolete]
		public PublicKeyNotFoundException( string message )
			: base( message ) { }

		/// <summary>
		/// Constructs a new <see cref="PublicKeyNotFoundException"/>
		/// </summary>
		public PublicKeyNotFoundException( Guid id, string source )
			: base( string.Format( "Could not find public key with id '{0}' from '{1}'", id, source ) ) { }
	}
}