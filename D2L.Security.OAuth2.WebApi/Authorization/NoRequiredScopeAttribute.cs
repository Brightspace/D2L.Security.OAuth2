using System;
using System.Web.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	[AttributeUsage( AttributeTargets.All, AllowMultiple = false )]
	internal sealed class NoRequiredScopeAttribute : AuthorizeAttribute {
		// This attribute is only used as a signal in DefaultAuthorizationAttribute
		protected override bool IsAuthorized( HttpActionContext context ) {
			return true;
		}
	}
}
