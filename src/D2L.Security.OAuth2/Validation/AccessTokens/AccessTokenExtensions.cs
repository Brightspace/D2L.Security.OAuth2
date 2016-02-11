using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal static class AccessTokenExtensions {
		/// <param name="token">An access token</param>
		/// <returns>The access token id. Returns null if one was not found.</returns>
		internal static string GetAccessTokenId( this IAccessToken token ) {
			return token.GetClaimValue( Constants.Claims.TOKEN_ID );
		}

		/// <param name="token">An access token</param>
		/// <returns>The tenant id. Returns null if one was not found.</returns>
		internal static string GetTenantId( this IAccessToken token ) {
			return token.GetClaimValue( Constants.Claims.TENANT_ID );
		}
		
		/// <param name="token">An access token</param>
		/// <returns>The scopes</returns>
		internal static IEnumerable<Scope> GetScopes( this IAccessToken token ) {
			string scopes = token.GetClaimValue( Constants.Claims.SCOPE );

			if( string.IsNullOrEmpty( scopes ) ) {
				return new Scope[] { };
			}

			Scope[] scopesArray = scopes
				.Split( ' ' )
				.Select( scopeString => Scope.Parse( scopeString ) )
				.Where( x => x != null )
				.ToArray();
			return scopesArray;
		}

		/// <param name="token">An access token</param>
		/// <returns>The user id. Returns null if one was not found.</returns>
		internal static string GetUserId( this IAccessToken token ) {
			return token.GetClaimValue( Constants.Claims.USER_ID );
		}

		/// <param name="token">An access token</param>
		/// <param name="claimName">The name of the claim whose value is returned</param>
		/// <returns>The claim value</returns>
		internal static string GetClaimValue( this IAccessToken token, string claimName ) {
			string claimValue = null;
			Claim claim = token.Claims.FirstOrDefault( x => x.Type == claimName );
			if( claim != null ) {
				claimValue = claim.Value;
			}

			return claimValue;
		}
	}
}
