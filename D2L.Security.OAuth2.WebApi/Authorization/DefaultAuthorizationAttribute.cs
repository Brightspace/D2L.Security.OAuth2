using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	public sealed class DefaultAuthorizationAttribute : AuthorizeAttribute {
		protected override bool IsAuthorized( HttpActionContext context ) {
			var principal = context.RequestContext.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			RequireScopeSpecification( context );
			RequirePrincipalTypeSpecification( context );

			return true;
		}

		private static void RequireScopeSpecification( HttpActionContext context ) {
			AuthorizeAttribute scopeAttribute = context.GetSingleAttribute<RequireScopeAttribute>();
			AuthorizeAttribute noScopeAttribute = context.GetSingleAttribute<NoRequiredScopeAttribute>();

			if( scopeAttribute != null && noScopeAttribute != null ) {
				throw new Exception( "Whoa - why does this action have a RequireScope and NoRequiredScope attribute???" );
			}

			if( scopeAttribute == null && noScopeAttribute == null ) {
				throw new Exception( "You must specify a scope with [RequireScope] or use [NoScope] for this API" );
			}
		}

		private static void RequirePrincipalTypeSpecification( HttpActionContext context ) {
			AuthorizeAttribute allowFromAttribute = context.GetSingleAttribute<AllowFromAttribute>();

			if ( allowFromAttribute == null ) {
				throw new Exception( "You must specify the types of callers for this API with [AllowFrom(...)]" );
			}
		}
	}
}
