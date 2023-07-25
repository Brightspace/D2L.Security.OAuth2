using System.Threading.Tasks;
using System.Web;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed partial class RequestAuthenticator {
		[GenerateSync]
		Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequest request
		) {
			string bearerToken = request.GetBearerTokenValue();

			return AuthenticateAsync( bearerToken );
		}
	}
}
