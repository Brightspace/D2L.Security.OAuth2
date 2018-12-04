using System;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Authorization.Exceptions;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Authorization {
	[AttributeUsage( AttributeTargets.All, AllowMultiple = false )]
	public sealed class RequireScopeAttribute : OAuth2AuthorizeAttribute {
		private readonly Scope m_requiredScope;

		public RequireScopeAttribute(
			string group,
			string resource,
			string permission
		) {
			if( string.IsNullOrWhiteSpace( group ) ) {
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

		protected override uint Order {
			get { return 1; }
		}

		protected override bool IsAuthorizedInternal( HttpActionContext actionContext ) {
			var principal = actionContext.ControllerContext.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			if( ScopeAuthorizer.IsAuthorized( principal.Scopes, m_requiredScope ) ) {
				return true;
			}

			throw new InsufficientScopeException( m_requiredScope );
		}
	}
}
