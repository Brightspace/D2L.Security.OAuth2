using System;

namespace BrowserAuthTokens.Default {
	public sealed class TokenProvider : ITokenProvider {
		public string TryGetTokenForUser( long userId, long duration ) {
			throw new NotImplementedException();
		}
	}
}