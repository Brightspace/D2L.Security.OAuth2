using System.Security.Principal;
using D2L.Security.RequestAuthentication;

namespace D2L.Security.WebApiAuthFilter {
	public interface ID2LPrincipalAdapter : ID2LPrincipal, IPrincipal { }
}
