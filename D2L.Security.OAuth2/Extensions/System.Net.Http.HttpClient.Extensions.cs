using System;
using System.Net.Http;
using System.Net.Http.Headers;
using D2L.Security.OAuth2.Principal;

namespace D2L {
#pragma warning disable 1591 // "Missing XML comment for ... __D2LSecurityOAuth2_Extensions 
	public static partial class __D2LSecurityOAuth2_Extensions {
#pragma warning restore 1591
		/// <summary>
		/// Populate the Authorization header with an access token from a principal (e.g. the current user being serviced by an API.)	
		/// </summary>
		/// <param name="this"></param>
		/// <param name="principal">This principals access token will be used</param>
		public static void AuthenticateAs( this HttpClient @this, ID2LPrincipal principal ) {
			@this.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
				scheme: "Bearer",
				parameter: principal.AccessToken.SensitiveRawAccessToken
			);	
		}
	}
}
