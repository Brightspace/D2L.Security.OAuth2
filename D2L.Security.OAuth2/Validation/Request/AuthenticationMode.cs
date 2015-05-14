namespace D2L.Security.OAuth2.Validation.Request {
	
	/// <summary>
	/// The modes in which authentication can be performed.
	/// </summary>
	public enum AuthenticationMode {

		/// <summary>
		/// Perform full authentication of a request
		/// </summary>
		Full,

		/// <summary>
		/// Do not perform Xsrf validation when authenticating a request. Use with extreme caution.
		/// </summary>
		SkipXsrfValidation
	}
}
