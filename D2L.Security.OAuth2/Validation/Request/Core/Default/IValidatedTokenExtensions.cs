using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.Token;

namespace D2L.Security.OAuth2.Validation.Request.Core.Default {
	internal static class IValidatedTokenExtensions {

		/// <param name="token">A validated token</param>
		/// <returns>The value of the Xsrf token. Returns null if one was not found.</returns>
		internal static string GetXsrfToken( this IValidatedToken token ) {
			return token.GetClaimValue( Constants.Claims.XSRF_TOKEN );
		}

		/// <param name="token">A validated token</param>
		/// <returns>The tenant id. Returns null if one was not found.</returns>
		internal static string GetTenantId( this IValidatedToken token ) {
			return token.GetClaimValue( Constants.Claims.TENANT_ID );
		}

		/// <param name="token">A validated token</param>
		/// <returns>The tenant url. Returns null if one was not found.</returns>
		internal static string GetTenantUrl( this IValidatedToken token ) {
			return token.GetClaimValue( Constants.Claims.TENANT_URL );
		}

		/// <param name="token">A validated token</param>
		/// <returns>The scopes</returns>
		internal static IEnumerable<Scope> GetScopes( this IValidatedToken token ) {
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

		/// <param name="token">A validated token</param>
		/// <returns>The user id. Returns null if one was not found.</returns>
		internal static string GetUserId( this IValidatedToken token ) {
			return token.GetClaimValue( Constants.Claims.USER_ID );
		}

		/// <param name="token">A validated token</param>
		/// <param name="claimName">The name of the claim whose value is returned</param>
		/// <returns>The claim value</returns>
		private static string GetClaimValue( this IValidatedToken token, string claimName ) {
			string claimValue = null;
			Claim claim = token.Claims.Where( x => x.Type == claimName ).FirstOrDefault();
			if( claim != null ) {
				claimValue = claim.Value;
			}

			return claimValue;
		}
	}
}
