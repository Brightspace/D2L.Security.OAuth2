namespace D2L.Security.RequestAuthentication.Core {
	
	/// <summary>
	/// Verifies authenticity via the basic components of a request
	/// </summary>
	interface ICoreAuthenticator {

		AuthenticationResult Authenticate(
			string cookie,
			string xsrfHeader,
			string bearerToken,
			out ID2LPrincipal principal
			);
	}
}
