namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// The possible results of token validation.
	/// </summary>
	public enum ValidationStatus {

		/// <summary>
		/// Token is expired
		/// </summary>
		Expired,

		/// <summary>
		/// Validation succeeded
		/// </summary>
		Success
	}
}
