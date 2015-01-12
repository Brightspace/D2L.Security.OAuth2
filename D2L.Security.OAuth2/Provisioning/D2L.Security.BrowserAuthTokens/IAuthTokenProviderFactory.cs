using D2L.Security.BrowserAuthTokens.Default;

namespace D2L.Security.BrowserAuthTokens {
	public interface IAuthTokenProviderFactory {
		AuthTokenProvider Create();
	}
}
