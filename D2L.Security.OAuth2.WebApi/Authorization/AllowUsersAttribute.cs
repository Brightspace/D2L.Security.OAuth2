using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	public sealed class AllowUsersAttribute : AuthorizeAttribute {
		protected override bool IsAuthorized( HttpActionContext context ) {
			var principal = context.RequestContext.Principal as ID2LPrincipal;

			return principal != null;
		}
	}
}
