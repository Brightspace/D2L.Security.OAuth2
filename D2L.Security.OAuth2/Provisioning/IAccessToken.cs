using System;

namespace D2L.Security.OAuth2.Provisioning {
	
	/// <summary>
	/// An abstraction for access tokens
	/// </summary>
	public interface IAccessToken {

		/// <summary>
		/// The raw token
		/// </summary>
		string Token { get; }

		/// <summary>
		/// Indicates how long the token is valid for
		/// </summary>
		TimeSpan ExpiresIn { get; }
	}
}
