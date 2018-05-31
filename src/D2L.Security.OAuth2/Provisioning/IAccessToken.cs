namespace D2L.Security.OAuth2.Provisioning {

	/// <summary>
	/// An abstraction for access tokens
	/// </summary>
	public interface IAccessToken {

		/// <summary>
		/// The raw token
		/// </summary>
		string Token { get; }
	}
}
