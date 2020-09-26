using System.Net.Http;
using System.Threading.Tasks;

#if !DNXCORE50
using System.Web;
#endif

using D2L.Services;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private static readonly ID2LPrincipal ANONYMOUS_PRINCIPAL = new AnonymousPrincipal();

		private readonly IAccessTokenValidator m_accessTokenValidator;

		internal RequestAuthenticator( IAccessTokenValidator accessTokenValidator ) {
			m_accessTokenValidator = accessTokenValidator;
		}

		Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequestMessage request
		) {
			string bearerToken = request.GetBearerTokenValue();

			return AuthenticateHelper( bearerToken );
		}

#if !DNXCORE50
		Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequest request
		) {
			string bearerToken = request.GetBearerTokenValue();

			return AuthenticateHelper( bearerToken );
		}
#endif

		private async Task<ID2LPrincipal> AuthenticateHelper(
			string bearerToken
		) {
			if( string.IsNullOrEmpty( bearerToken ) ) {
				return ANONYMOUS_PRINCIPAL;
			}

			IAccessToken accessToken = await m_accessTokenValidator
				.ValidateAsync( bearerToken )
				.ConfigureAwait( false );

			ID2LPrincipal principal = new D2LPrincipal( accessToken );

			return principal;
		}
	}
}
