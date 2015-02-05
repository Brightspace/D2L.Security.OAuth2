using System;
using D2L.Security.BrowserAuthTokens.Default;

namespace D2L.Security.BrowserAuthTokens {
	public static class AuthTokenProviderFactory {
		
		public static IAuthTokenProvider Create( 
			IAssertionGrantSigner signer, 
			Uri authServiceEndpoint 
			) {

			return new AuthTokenProvider();
		}
	}
}
