namespace D2L.Security.OAuth2.Validation.Exceptions {

	/// <summary>
	/// An exception indicating that the request was blocked for XSRF concerns
	/// </summary>
	public sealed class XsrfException : ValidationException {

		/// <summary>
		/// Constructs a new <see cref="XsrfException"/>
		/// </summary>
		public XsrfException( string message ) : base( message ) {}
	}
}
