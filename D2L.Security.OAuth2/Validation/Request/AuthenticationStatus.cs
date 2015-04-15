namespace D2L.Security.OAuth2.Validation.Request {
	public enum AuthenticationStatus {
		
		/// <summary>
		/// Security token is expired
		/// </summary>
		Expired,
		
		/// <summary>
		/// Security token was supplied in more than one location
		/// </summary>
		LocationConflict,
		
		/// <summary>
		/// Security token was not supplied
		/// </summary>
		Anonymous,

		/// <summary>
		/// Xsrf token did not match
		/// </summary>
		XsrfMismatch,

		/// <summary>
		/// Authentication was successful
		/// </summary>
		Success
	}
}
