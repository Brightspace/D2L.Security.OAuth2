using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
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

			bool hasClaim = principal
				.AccessToken
				.Claims
				.HasClaim( m_claimType );

			return hasClaim;
		}

		protected override void HandleUnauthorizedRequestInternal(
			HttpActionContext actionContext
		) {
			var response = actionContext
				.Request
				.CreateErrorResponse(
					HttpStatusCode.Forbidden,
					String.Format( "Missing claim: '{0}'", m_claimType )
				);

			actionContext.Response = response;
		}
	}
}
