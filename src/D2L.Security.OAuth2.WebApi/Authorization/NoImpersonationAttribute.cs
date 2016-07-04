using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Authorization {
	/// <summary>
	/// Block requests where the access token indicates user impersonation
	/// </summary>
	[AttributeUsage( AttributeTargets.All, AllowMultiple = false )]
	public sealed class NoImpersonationAttribute : OAuth2AuthorizeAttribute {
		protected override uint Order {
      get { return 0; }
    }

		protected override bool IsAuthorizedInternal( HttpActionContext actionContext ) {
			var principal = actionContext
				.ControllerContext
				.RequestContext
				.Principal as ID2LPrincipal;

			if ( principal == null ) {
				return true;
			}

			if ( principal.Type != PrincipalType.User ) {
				return true;
			}

			return principal.ActualUserId == principal.UserId;
		}

		protected override void HandleUnauthorizedRequestInternal(
			HttpActionContext actionContext
		) {
			var response = actionContext
				.Request
				.CreateErrorResponse(
					HttpStatusCode.Forbidden,
					"This API is not usable while impersonating. This error message indicates a bug in the client application which is responsible for knowing this."
				);

			actionContext.Response = response;
		}
	}
}
