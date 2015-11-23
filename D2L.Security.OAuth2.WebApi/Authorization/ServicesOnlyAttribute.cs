using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	public sealed class ServicesOnlyAttribute : AuthorizeAttribute {
		protected override bool IsAuthorized( HttpActionContext context ) {
			var principal = context.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			// Sigh...
			long userId;
			if( long.TryParse( principal.UserId, out userId ) ) {
				return false;
			}

			return true;
		}

		internal bool IsAuthorizedHelper( HttpActionContext context ) {
			return this.IsAuthorized( context );
		}
	}
}
