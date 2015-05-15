namespace D2L.Security.OAuth2.Validation.AccessTokens {

	/// <summary>
	/// Contains the status and token of a token validation attempt
	/// </summary>
	public interface IValidationResponse {

		/// <summary>
		/// Indicates the success or failure of the token validation
		/// </summary>
		ValidationStatus Status { get; }

		/// <summary>
		/// The token
		/// </summary>
		IAccessToken AccessToken { get; }
	}
}
