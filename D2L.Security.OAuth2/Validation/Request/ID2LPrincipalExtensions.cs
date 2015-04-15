using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace D2L.Security.OAuth2.Validation.Request {
	public static class ID2LPrincipalExtensions {

		/// <summary>
		/// Gets the id of the access token from which this principal was created.
		/// The access token id is intended for logging purposes
		/// </summary>
		/// <returns>
		///		The access token id, or empty string when the access token id could not be found
		/// </returns>
		public static string GetAccessTokenId( this ID2LPrincipal principal ) {
			try {
				return GetAccessTokenIdWorker( principal );
			} catch {
				return "";
			}
		}

		private static string GetAccessTokenIdWorker( ID2LPrincipal principal ) {
			IEnumerable<Claim> claims = principal.AllClaims;
			Claim tokenIdClaim = claims.FirstOrDefault( x => x.Type == Constants.Claims.TOKEN_ID );
			string tokenId = tokenIdClaim.Value ?? "";

			return tokenId;
		}
	}
}
