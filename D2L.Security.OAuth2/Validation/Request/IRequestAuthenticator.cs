using System.Net.Http;
using System.Web;

namespace D2L.Security.OAuth2.Validation.Request {
	public interface IRequestAuthenticator {
		AuthenticationResult AuthenticateAndExtract( HttpRequestMessage request, out ID2LPrincipal principal );
		AuthenticationResult AuthenticateAndExtract( HttpRequest request, out ID2LPrincipal principal );
	}
}
