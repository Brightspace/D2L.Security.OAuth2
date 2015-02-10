using System;

namespace D2L.Security.BrowserAuthTokens {
	
	public interface IAccessToken {
		string Token { get; }

		/// <summary>
		/// Lifetime of this access token
		/// </summary>
		TimeSpan ExpiresIn { get; }
	}
}
