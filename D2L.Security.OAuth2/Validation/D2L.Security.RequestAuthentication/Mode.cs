namespace D2L.Security.RequestAuthentication {
	
	public enum Mode {
		/// <summary>
		/// This mode will perform full authentication of the request
		/// </summary>
		Full,

		/// <summary>
		/// By choosing this mode, Xsrf validation will not be performed.
		/// Use with extreme caution.
		/// </summary>
		SkipXsrfValidation
	}
}
