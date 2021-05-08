using D2L.Security.OAuth2.Principal;
using System.Threading.Tasks;
using System.Web;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed partial class RequestAuthenticator {
		Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequest request
		) {
			string bearerToken = request.GetBearerTokenValue();

			return AuthenticateAsync( bearerToken );
		}
	}
}
