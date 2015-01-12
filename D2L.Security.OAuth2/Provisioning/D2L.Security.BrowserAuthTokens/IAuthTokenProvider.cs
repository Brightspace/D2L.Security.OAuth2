namespace D2L.Security.BrowserAuthTokens {
	public interface IAuthTokenProvider {
		string GetTokenForUser( string tenantId, long userId, string xsrfToken, long duration );
	}
}