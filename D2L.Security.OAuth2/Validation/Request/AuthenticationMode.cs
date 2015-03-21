namespace D2L.Security.OAuth2.Validation.Request {
	
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
