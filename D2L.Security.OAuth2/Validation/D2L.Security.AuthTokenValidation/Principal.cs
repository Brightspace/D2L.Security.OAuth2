using System.Collections.Generic;

namespace D2L.Security.AuthTokenValidation {

	public sealed class Principal {

		public Principal(
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

		public HashSet<string> Scopes { get; private set; }

		public long UserId { get; private set; }

		public string TenantId { get; private set; }

		public string XsrfToken { get; private set; }

		public bool IsBrowserUser { get { return XsrfToken != null; } }

		public bool HasScope( string scope ) {
			return Scopes.Contains( "*" ) || Scopes.Contains( scope );
		}

		public void AssertScope( string scope ) {
			if( !HasScope( scope ) ) {
				throw new AuthorizationException( string.Format( "Not authorized for scope '{0}'", scope ) );
			}
		}
	}
}