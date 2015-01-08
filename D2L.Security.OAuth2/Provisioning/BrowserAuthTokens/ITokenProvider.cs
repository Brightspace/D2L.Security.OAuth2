namespace BrowserAuthTokens {
	public interface ITokenProvider {
		string TryGetTokenForUser( long userId, long duration );
	}
}