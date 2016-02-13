using System.Web.Http.Filters;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authentication {
	public interface ID2LPrincipalDependencyRegistry {
		void Register( HttpAuthenticationContext context, ID2LPrincipal principal );
	}
}