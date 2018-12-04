using System;
using System.Web.Http.Controllers;
using D2L.Security.OAuth2.Authorization.Exceptions;
using D2L.Security.OAuth2.Principal;
using D2L.Services;

namespace D2L.Security.OAuth2.Authorization {
	[AttributeUsage( AttributeTargets.All, AllowMultiple = false )]
	public sealed class RequireClaimAttribute : OAuth2AuthorizeAttribute {
		private readonly string m_claimType;

		public RequireClaimAttribute( string claimType ) {
			m_claimType = claimType;
		}

		protected override uint Order {
			get {
				return 2;
			}
		}

		protected override bool IsAuthorizedInternal( HttpActionContext actionContext ) {
			var principal = actionContext
				.ControllerContext
				.RequestContext
				.Principal as ID2LPrincipal;

			if( principal == null ) {
				return false;
			}

			if( principal.AccessToken.Claims.HasClaim( m_claimType ) ) {
				return true;
			}

			throw new OAuth2Exception(
				error: OAuth2Exception.Type.invalid_token,
				errorDescription: $"Missing claim: '{ m_claimType }'"
			);
		}
	}
}
