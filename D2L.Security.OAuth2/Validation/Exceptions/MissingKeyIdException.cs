using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {
	
	/// <summary>
	/// Exception indicating that a key id is missing
	/// </summary>
	public class MissingKeyIdException : Exception {

		/// <summary>
		/// Constructs a new <see cref="MissingKeyIdException"/>
		/// </summary>
		public MissingKeyIdException( string message ) : base( message ) {}

	}
}
