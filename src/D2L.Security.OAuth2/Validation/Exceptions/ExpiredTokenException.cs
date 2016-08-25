using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// Exception indicating that the JWT is expired
	/// </summary>
	public sealed class ExpiredTokenException : ValidationException {

		private const string MESSAGE = "The access token is expired";

		/// <summary>
		/// Constructs a new <see cref="ExpiredTokenException"/>
		/// </summary>
		public ExpiredTokenException() : base( MESSAGE ) {}


		/// <summary>
		/// Constructs a new <see cref="ExpiredTokenException"/>
		/// </summary>
		public ExpiredTokenException( Exception inner ) : base( MESSAGE, inner ) {}

	}
}
