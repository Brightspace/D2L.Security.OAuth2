using System.Net.Http;
using System.Web;
using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Default {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private readonly IAuthTokenValidator m_tokenValidator;

		internal RequestAuthenticator( IAuthTokenValidator tokenValidator ) {
			m_tokenValidator = tokenValidator;
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequestMessage request, out ID2LPrincipal principal ) {
			principal = new D2LPrincipal();
			return AuthenticationResult.Success;
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequest request, out ID2LPrincipal principal ) {
			principal = new D2LPrincipal();
			return AuthenticationResult.Success;
		}
	}
}
