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
			AuthorizeAttribute scopeAttribute = context.ActionDescriptor.GetCustomAttributes<RequireScopeAttribute>().SingleOrDefault();
			AuthorizeAttribute noScopeAttribute = context.ActionDescriptor.GetCustomAttributes<NoRequiredScopeAttribute>().SingleOrDefault();

			if( scopeAttribute != null && noScopeAttribute != null ) {
				throw new Exception( "The attributes [RequireScope(...)] and [NoScope] are mutually exclusive" );
			}

			if( scopeAttribute == null && noScopeAttribute == null ) {
				throw new Exception( "You must specify a scope with [RequireScope] or use [NoScope] for this API" );
			}
		}

		private static void RequirePrincipalTypeSpecification( HttpActionContext context ) {
			var allowFromAttribute = context.ActionDescriptor.GetCustomAttributes<AllowFromAttribute>().SingleOrDefault();
			var allowFromAttribute2 = context.ActionDescriptor.ControllerDescriptor.ControllerType.GetCustomAttributes( typeof( AllowFromAttribute ), inherit: false ).SingleOrDefault();

			if ( allowFromAttribute == null && allowFromAttribute2 == null ) {
				throw new Exception( "You must specify the types of callers for this API with [AllowFrom(...)]" );
			}
		}
	}
}
