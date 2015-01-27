using System.Security.Principal;
using D2L.Security.RequestAuthentication;

namespace D2L.Security.WebApiAuthFilter.Principal {

	/// <summary>
	/// Adapts ID2LPrincipal so it can be assigned to an IPrincipal on the thread context.
	/// </summary>
	public interface ID2LPrincipalAdapter : ID2LPrincipal, IPrincipal { }
}
