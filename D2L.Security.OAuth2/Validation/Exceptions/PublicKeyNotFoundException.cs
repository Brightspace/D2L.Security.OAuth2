namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the public key could not be found
	/// </summary>
	public sealed class PublicKeyNotFoundException : ValidationException {

		/// <summary>
		/// Constructs a new <see cref="PublicKeyNotFoundException"/>
		/// </summary>
		public PublicKeyNotFoundException( string message ) : base( message ) {}
	}
}