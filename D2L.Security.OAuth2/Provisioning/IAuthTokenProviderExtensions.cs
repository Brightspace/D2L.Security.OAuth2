using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Provisioning {
	public static class IAuthTokenProviderExtensions {

		public static Task<IAccessToken> ProvisionAccessTokenAsync(
			this IAuthTokenProvider @this,
			ClaimSet claimSet,
			IEnumerable<string> scopes,
			SecurityToken signingToken
		) {
			IEnumerable<Scope> strongScopes = ParseScopes( scopes );

			return @this.ProvisionAccessTokenAsync( claimSet, strongScopes, signingToken );
		}

		public static IAccessToken ProvisionAccessToken(
			this IAuthTokenProvider @this,
			ClaimSet claimSet,
			IEnumerable<string> scopes,
			SecurityToken signingToken
		) {
			IEnumerable<Scope> strongScopes = ParseScopes( scopes );

			var token = @this.ProvisionAccessToken( claimSet, strongScopes, signingToken );
			return token;
		}

		private static IEnumerable<Scope> ParseScopes( IEnumerable<string> scopeStrings ) {
			foreach( var scopeString in scopeStrings ) {
				Scope scope;
				if( Scope.TryParse( scopeString, out scope ) ) {
					yield return scope;
				}
			}
		}

	}
}
