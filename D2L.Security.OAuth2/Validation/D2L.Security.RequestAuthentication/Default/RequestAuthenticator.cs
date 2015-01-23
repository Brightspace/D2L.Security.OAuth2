using System.Net.Http;
using System.Web;
using D2L.Security.RequestAuthentication.Core;

namespace D2L.Security.RequestAuthentication.Default {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private const string COOKIE_NAME = "d2lApi";

		private readonly ICoreAuthenticator m_coreAuthenticator;

		internal RequestAuthenticator( ICoreAuthenticator coreAuthenticator ) {
			m_coreAuthenticator = coreAuthenticator;
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequestMessage request, out ID2LPrincipal principal ) {
			string cookie = request.GetCookieValue( COOKIE_NAME );
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return m_coreAuthenticator.Authenticate( cookie, xsrfToken, bearerToken, out principal );
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequest request, out ID2LPrincipal principal ) {
			string cookie = request.GetCookieValue( COOKIE_NAME );
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return m_coreAuthenticator.Authenticate( cookie, xsrfToken, bearerToken, out principal );
		}
	}
}
