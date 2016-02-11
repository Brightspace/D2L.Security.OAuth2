namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the JWT is expired
	/// </summary>
	public sealed class ExpiredTokenException : ValidationException {

		/// <summary>
		/// Constructs a new <see cref="ExpiredTokenException"/>
		/// </summary>
		public ExpiredTokenException( string message ) : base( message ) {}
	}
}
