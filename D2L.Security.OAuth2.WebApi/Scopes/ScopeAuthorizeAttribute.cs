using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Scopes {
	public sealed class ScopeAuthorizeAttribute : AuthorizeAttribute {
		private readonly Scope m_requiredScope;

		public ScopeAuthorizeAttribute(
			string group,
			string resource,
			string permission
		) {
			if(  string.IsNullOrWhiteSpace( group ) ) {
				throw new ArgumentException( "group cannot be null or empty.", "group" );
			}
			if( string.IsNullOrWhiteSpace( resource ) ) {
				throw new ArgumentException( "resource cannot be null or empty.", "resource" );
			}
			if( string.IsNullOrWhiteSpace( permission ) ) {
				throw new ArgumentException( "permission cannot be null or empty.", "permission" );
			}

			m_requiredScope = new Scope( group, resource, permission );
		}

		protected override bool IsAuthorized( HttpActionContext actionContext ) {
			var principal =
				Thread.CurrentPrincipal as ID2LPrincipal ??
				actionContext.ControllerContext.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( principal.Scopes, m_requiredScope );

			return isAuthorized;
		}

		protected override void HandleUnauthorizedRequest( HttpActionContext actionContext ) {
			var response = actionContext.Request.CreateErrorResponse( HttpStatusCode.Forbidden, "insufficient_scope" );
			response.Headers.Add( "WWW-Authenticate", "Bearer error=\"insufficient_scope\"" );

			actionContext.Response = response;
		}
	}
}
