using System;
using System.Collections.Generic;

namespace D2L.Security.RequestAuthentication {
	public interface ID2LPrincipal {
		long? UserId { get; }
		string TenantId { get; }
		string TenantUrl { get; }

		PrincipalType Type { get; }

		IEnumerable<string> Scopes { get; }

		/// <summary>
		/// The expiration date of the security information provided with the request
		/// </summary>
		DateTime SecurityExpiry { get; }

		[Obsolete("Temporary")]
		string Xsrf { get; }

		[Obsolete( "Temporary" )]
		string AccessToken { get; }
	}
}
