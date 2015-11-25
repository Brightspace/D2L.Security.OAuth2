using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	[AttributeUsage( AttributeTargets.All, AllowMultiple = false )]
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
			AuthorizeAttribute scopeAttribute = context.ActionDescriptor.GetCustomAttributes<RequireScopeAttribute>().Single();
			AuthorizeAttribute noScopeAttribute = context.ActionDescriptor.GetCustomAttributes<NoRequiredScopeAttribute>().Single();

			if( scopeAttribute != null && noScopeAttribute != null ) {
				throw new Exception( "The attributes [RequireScope(...)] and [NoScope] are mutually exclusive" );
			}

			if( scopeAttribute == null && noScopeAttribute == null ) {
				throw new Exception( "You must specify a scope with [RequireScope] or use [NoScope] for this API" );
			}
		}

		private static void RequirePrincipalTypeSpecification( HttpActionContext context ) {
			AuthorizeAttribute allowFromAttribute = context.ActionDescriptor.GetCustomAttributes<AllowFromAttribute>().Single();

			if ( allowFromAttribute == null ) {
				throw new Exception( "You must specify the types of callers for this API with [AllowFrom(...)]" );
			}
		}
	}
}
