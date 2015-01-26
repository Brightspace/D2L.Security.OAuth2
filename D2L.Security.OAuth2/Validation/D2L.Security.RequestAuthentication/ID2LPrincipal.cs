using System;
using System.Collections.Generic;

namespace D2L.Security.RequestAuthentication {
	public interface ID2LPrincipal {
		long? UserId { get; }
		string ClientId { get; }
		string TenantId { get; }
		string TenantUrl { get; }

		bool IsBrowserUser { get; }
		bool IsService { get; }

		IEnumerable<string> Scopes { get; }
	}
}
