using System;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Authorization.Exceptions;
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

			if( principal == null ) {
				return false;
			}

			if( principal.Type != PrincipalType.User ) {
				return true;
			}

			if( principal.UserId == principal.ActualUserId ) {
				return true;
			}

			throw new OAuth2Exception(
				error: OAuth2Exception.Type.invalid_token,
				errorDescription: "This API is not usable while impersonating. This error message indicates a bug in the client application which is responsible for knowing this."
			);
		}
	}
}
