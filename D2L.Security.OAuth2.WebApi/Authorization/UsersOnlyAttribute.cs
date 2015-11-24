using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	public sealed class UsersOnlyAttribute : AuthorizeAttribute {
		protected override bool IsAuthorized( HttpActionContext context ) {
			var principal = context.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			return principal.Type == PrincipalType.User;
		}

		internal bool IsAuthorizedHelper( HttpActionContext context ) {
			return this.IsAuthorized( context );
		}

		protected override void HandleUnauthorizedRequest( HttpActionContext actionContext ) {
			var response = actionContext.Request.CreateErrorResponse( HttpStatusCode.Forbidden, "users_only" );
			response.Headers.Add( "WWW-Authenticate", "Bearer error=\"users_only\"" );

			actionContext.Response = response;
		}
	}
}
