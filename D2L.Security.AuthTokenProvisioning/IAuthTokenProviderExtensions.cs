using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning {
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
			IEnumerable<Scope> scopes,
			SecurityToken signingToken
		) {
			var token = @this.ProvisionAccessTokenAsync( claimSet, scopes, signingToken ).Result;
			return token;
		}

		public static IAccessToken ProvisionAccessToken(
			this IAuthTokenProvider @this,
			ClaimSet claimSet,
			IEnumerable<string> scopes,
			SecurityToken signingToken
		) {
			var token = @this.ProvisionAccessTokenAsync( claimSet, scopes, signingToken ).Result;
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
