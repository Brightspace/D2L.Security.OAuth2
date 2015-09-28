using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;

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
			var principal = actionContext.ControllerContext.RequestContext.Principal as ClaimsPrincipal;
			if( principal == null ) {
				return false;
			}

			var grantedScopes = principal.GetGrantedScopes();

			bool isAuthorized = ScopeAuthorizer.IsAuthorized( grantedScopes, m_requiredScope );

			return isAuthorized;
		}

		protected override void HandleUnauthorizedRequest( HttpActionContext actionContext ) {
			var response = actionContext.Request.CreateErrorResponse( HttpStatusCode.Forbidden, "insufficient_scope" );
			response.Headers.Add( "WWW-Authenticate", "Bearer error=\"insufficient_scope\"" );

			actionContext.Response = response;
		}
	}
}
