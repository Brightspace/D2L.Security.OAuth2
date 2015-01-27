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
			string xsrfToken = null;
			Claim xsrfClaim = token.Claims.Where( x => x.Type == XSRF_TOKEN_CLAIM_NAME ).FirstOrDefault();
			if( xsrfClaim != null ) {
				xsrfToken = xsrfClaim.Value;
			}

			return xsrfToken;
		}
	}
}
