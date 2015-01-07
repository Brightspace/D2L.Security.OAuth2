using System.Collections.Generic;

namespace D2L.Security.AuthTokenValidation {

	internal sealed class UserPrincipal : Principal {

		public UserPrincipal(
			long userId,
			string tenantId,
			string xsrfToken,
			HashSet<string> scopes 
			) {

			UserId = userId;
			TenantId = tenantId;
			XsrfToken = xsrfToken;
			Scopes = scopes;
		}

		public long UserId { get; private set; }

		public string TenantId { get; private set; }

		public string XsrfToken { get; private set; }

		public bool IsBrowserUser { get { return XsrfToken != null; } }
	}
}