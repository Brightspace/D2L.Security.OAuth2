using System;

namespace D2L.Security.OAuth2.Validation.Exceptions {
	public class MissingKeyIdException : Exception {

		public MissingKeyIdException( string message ) : base( message ) {}

	}
}
