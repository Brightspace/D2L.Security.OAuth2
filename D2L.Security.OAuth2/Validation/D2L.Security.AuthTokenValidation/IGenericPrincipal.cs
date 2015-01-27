using System.Collections.Generic;

namespace D2L.Security.AuthTokenValidation {

	public interface IGenericPrincipal : System.Security.Principal.IPrincipal {

		HashSet<string> Scopes { get; }
		long UserId { get; }
		string TenantId { get; }
		string TenantFullyQualifiedDomainName { get; }
		string XsrfToken { get; }
		bool IsBrowserUser { get; }
		bool HasScope( string scope );
		void AssertScope( string scope );

		string Jwt { get; }
	}
}