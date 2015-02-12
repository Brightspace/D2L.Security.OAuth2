﻿using System;
using System.Collections.Generic;

namespace D2L.Security.RequestAuthentication {
	public interface ID2LPrincipal {
		string UserId { get; }
		string TenantId { get; }
		string TenantUrl { get; }

		PrincipalType Type { get; }

		IEnumerable<string> Scopes { get; }

		/// <summary>
		/// The expiration date of the access token provided with the request
		/// </summary>
		DateTime AccessTokenExpiry { get; }

		[Obsolete("Temporary")]
		string Xsrf { get; }

		[Obsolete( "Temporary" )]
		string AccessToken { get; }
	}
}
