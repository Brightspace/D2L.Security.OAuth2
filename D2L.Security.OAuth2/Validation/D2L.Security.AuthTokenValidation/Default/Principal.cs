using System.Collections.Generic;
using System.Security.Principal;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class Principal : IGenericPrincipal {

		public Principal(
			long userId,
			string tenantId,
			string tenantFullyQualifiedDomainName,
			string xsrfToken,
			HashSet<string> scopes,
			string jwt
			) {

			UserId = userId;
			TenantId = tenantId;
			TenantFullyQualifiedDomainName = tenantFullyQualifiedDomainName;
			XsrfToken = xsrfToken;
			Scopes = scopes;
			Jwt = jwt;
		}

		public HashSet<string> Scopes { get; private set; }

		public long UserId { get; private set; }

		public string TenantId { get; private set; }
		public string TenantFullyQualifiedDomainName { get; private set; }

		public string XsrfToken { get; private set; }

		public bool IsBrowserUser { get { return XsrfToken != null; } }

		public bool HasScope( string scope ) {
			return Scopes.Contains( scope );
		}

		public void AssertScope( string scope ) {
			if( !HasScope( scope ) ) {
				throw new AuthorizationException( string.Format( "Not authorized for scope '{0}'", scope ) );
			}
		}

		public bool IsInRole( string role ) {
			throw new System.NotImplementedException();
		}

		public IIdentity Identity {
			get { throw new System.NotImplementedException(); }
		}

		public string Jwt { get; private set; }

		IIdentity IPrincipal.Identity {
			get { throw new System.NotImplementedException(); }
		}

		bool IPrincipal.IsInRole( string role ) {
			throw new System.NotImplementedException();
		}
	}
}