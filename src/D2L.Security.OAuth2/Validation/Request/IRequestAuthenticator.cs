using System.Net.Http;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Validation.Request {
	public partial interface IRequestAuthenticator {
		/// <summary>
		/// Authenticates a token contained in an <see cref="HttpRequestMessage"/>
		/// </summary>
		/// <param name="request">The web request object</param>
		/// <returns>An <see cref="ID2LPrincipal"/> for an authenticated user.</returns>
		[GenerateSync]
		Task<ID2LPrincipal> AuthenticateAsync(
			HttpRequestMessage request
		);

		/// <summary>
		/// Authenticates a token.
		/// </summary>
		/// <param name="bearerToken">The bearer token.</param>
		/// <returns>An <see cref="ID2LPrincipal"/> for an authenticated user.</returns>
		[GenerateSync]
		Task<ID2LPrincipal> AuthenticateAsync(
			string bearerToken
		);
	}
}
