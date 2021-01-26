using D2L.Security.OAuth2.Principal;
using System.Threading.Tasks;
using System.Web;

namespace D2L.Security.OAuth2.Validation.Request {
	public partial interface IRequestAuthenticator {
		/// <summary>
		/// Authenticates a token contained in an <see cref="HttpRequest"/>
		/// </summary>
		/// <param name="request">The web request object.</param>
		/// <returns>An <see cref="ID2LPrincipal"/> for an authenticated user.</returns>
		Task<ID2LPrincipal> AuthenticateAsync( HttpRequest request );
	}
}
