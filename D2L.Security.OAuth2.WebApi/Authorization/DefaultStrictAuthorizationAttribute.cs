using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	public sealed class DefaultStrictAuthorizationAttribute : AuthorizeAttribute {
		private static readonly RequireScopeAttribute m_conservativeScopeChecker = new RequireScopeAttribute( "*", "*", "*" );
		private static readonly ServicesOnlyAttribute m_conservativePrincipalTypeChecker = new ServicesOnlyAttribute();

		protected override bool IsAuthorized( HttpActionContext context ) {
			// This check is redundant in a couple of ways but it's good as a fail-safe.
			var principal = context.RequestContext.Principal as ID2LPrincipal;
			if( principal == null ) {
				return false;
			}

			if ( !ScopesAreOk( context )) {
				return false;
			}

			if ( !PrincipalTypeIsOk( context )) {
				return false;	
			}

			return true;
		}

		private bool ScopesAreOk( HttpActionContext context ) {
			AuthorizeAttribute scopeAttribute = context.GetSingleAttribute<RequireScopeAttribute>();
			AuthorizeAttribute noScopeAttribute = context.GetSingleAttribute<NoRequiredScopeAttribute>();

			if( scopeAttribute != null && noScopeAttribute != null ) {
				throw new Exception( "Whoa - why does this action have a RequireScope and NoRequiredScope attribute???" );
			}

			if( scopeAttribute == null && noScopeAttribute == null ) {
				return m_conservativeScopeChecker.IsAuthorizedHelper( context );
			}

			return true;
		}

		private bool PrincipalTypeIsOk( HttpActionContext context ) {
			AuthorizeAttribute allowUsersAttribute = context.GetSingleAttribute<AllowUsersAndServicesAttribute>();
			AuthorizeAttribute servicesOnlyAttribute = context.GetSingleAttribute<ServicesOnlyAttribute>();

			if ( allowUsersAttribute != null && servicesOnlyAttribute != null ) {
				throw new Exception( "Whoa - why does this action have an AllowUsers and ServicesOnly attribute???" );
			}

			if ( allowUsersAttribute == null && servicesOnlyAttribute == null ) {
				return m_conservativePrincipalTypeChecker.IsAuthorizedHelper( context );
			}

			return true;
		}
	}
}
