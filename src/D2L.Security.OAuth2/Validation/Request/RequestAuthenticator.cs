using System.Net.Http;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed partial class RequestAuthenticator : IRequestAuthenticator {

		private static readonly ID2LPrincipal ANONYMOUS_PRINCIPAL = new AnonymousPrincipal();

		private readonly IAccessTokenValidator m_accessTokenValidator;

		internal RequestAuthenticator( IAccessTokenValidator accessTokenValidator ) {
			m_accessTokenValidator = accessTokenValidator;
		}

		[GenerateSync]
		async Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequestMessage request
		) {
			string bearerToken = request.GetBearerTokenValue();

			return await AuthenticateAsync( bearerToken ).ConfigureAwait(false);
		}

		[GenerateSync]
		public async Task<ID2LPrincipal> AuthenticateAsync(
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
