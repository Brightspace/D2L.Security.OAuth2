using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal static class IValidatedTokenExtensions {

		private const string XSRF_TOKEN_CLAIM_NAME = "xt";
		private const string USER_ID_CLAIM_NAME = "uid";
		private const string TENANT_ID_CLAIM_NAME = "tid";
		private const string SCOPE_CLAIM_NAME = "scope";

		/// <summary>
		/// Returns the Xsrf token from a validated token.
		/// </summary>
		/// <param name="token">A validated token</param>
		/// <returns>The value of the Xsrf token. Returns null if one was not found.</returns>
		internal static string GetXsrfToken( this IValidatedToken token ) {
			return token.GetClaimValue( XSRF_TOKEN_CLAIM_NAME );
		}

		/// <summary>
		/// Returns the tenant id from a validated token.
		/// </summary>
		/// <param name="token">A validated token</param>
		/// <returns>The tenant id. Returns null if one was not found.</returns>
		internal static string GetTenantId( this IValidatedToken token ) {
			return token.GetClaimValue( TENANT_ID_CLAIM_NAME );
		}

		/// <summary>
		/// Returns the scopes from a validated token.
		/// </summary>
		/// <param name="token">A validated token</param>
		/// <returns>The scopes</returns>
		internal static IEnumerable<string> GetScopes( this IValidatedToken token ) {
			string scopes = token.GetClaimValue( SCOPE_CLAIM_NAME );

			if( string.IsNullOrEmpty( scopes ) ) {
				return new string[] { };
			}

			string[] scopesArray = scopes.Split( ' ' );
			return scopesArray;
		}

		/// <summary>
		/// Returns the user id from a validated token.
		/// </summary>
		/// <param name="token">A validated token</param>
		/// <returns>The user id. Returns null if one was not found.</returns>
		internal static long? GetUserId( this IValidatedToken token ) {
			string userIdString = token.GetClaimValue( USER_ID_CLAIM_NAME );

			if( userIdString == null ) {
				return null;
			}

			long result;
			if( !long.TryParse( userIdString, out result ) ) {
				return null;
			}

			return result;
		}

		/// <summary>
		/// Gets the value of the claim with the specified name
		/// </summary>
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
