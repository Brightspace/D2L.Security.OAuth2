using System.Net.Http;
using System.Threading.Tasks;
using System.Web;

using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {

	/// <summary>
	/// An abstraction for authenticating access tokens that works at the request level 
	/// rather than the token level (see <see cref="IAccessTokenValidator"/>)
	/// </summary>
	public interface IRequestAuthenticator {

		/// <summary>
		/// Authenticates a token contained in an <see cref="HttpRequestMessage"/>
		/// </summary>
		/// <param name="request">The web request object</param>
		/// <param name="authMode">The authentication mode; xsrf validation should NOT be 
		/// skipped for requests coming from a browser</param>
		/// <returns>An <see cref="ID2LPrincipal"/> for an authenticated user.</returns>
		Task<ID2LPrincipal> AuthenticateAsync(
			HttpRequestMessage request,
			AuthenticationMode authMode = AuthenticationMode.Full
		);

		/// <summary>
		/// Authenticates a token contained in an <see cref="HttpRequest"/>
		/// </summary>
		/// <param name="request">The web request object.</param>
		/// <param name="authMode">The authentication mode. Xsrf validation should NOT 
		/// be skipped for requests coming from a browser</param>
		/// <returns>An <see cref="ID2LPrincipal"/> for an authenticated user.</returns>
		Task<ID2LPrincipal> AuthenticateAsync(
			HttpRequest request,
			AuthenticationMode authMode = AuthenticationMode.Full
		);
	}
}
