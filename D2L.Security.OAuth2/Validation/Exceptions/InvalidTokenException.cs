namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the format of the JWT to be validated was somehow invalid.
	/// </summary>
	public sealed class InvalidTokenException : ValidationException {
		
		/// <summary>
		/// Constructs a new <see cref="InvalidTokenException"/>
		/// </summary>
		public InvalidTokenException( string message ) : base( message ) {}
	}
}
