using System.Linq;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal static class IValidatedTokenExtensions {

		private const string XSRF_TOKEN_CLAIM_NAME = "xt";

		/// <summary>
		/// Returns the Xsrf token from a validated token.
		/// </summary>
		/// <param name="token">A validated token</param>
		/// <returns>The value of the Xsrf token. Returns null if one was not found.</returns>
		internal static string GetXsrfToken( this IValidatedToken token ) {
			return token.GetClaimValue( XSRF_TOKEN_CLAIM_NAME );
		}

		/// <summary>
		/// Gets the value of the claim with the specified name
		/// </summary>
		/// <param name="token">A validated token</param>
		/// <param name="claimName">The name of the claim whose value is returned</param>
		/// <returns>The claim value</returns>
		internal static string GetClaimValue( this IValidatedToken token, string claimName ) {
			string claimValue = null;
			Claim claim = token.Claims.Where( x => x.Type == claimName ).FirstOrDefault();
			if( claim != null ) {
				claimValue = claim.Value;
			}

			return claimValue;
		}
	}
}
