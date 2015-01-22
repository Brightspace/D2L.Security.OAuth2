using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuthFilter {

	[AttributeUsage( AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false )]
	internal sealed class AuthenticationFilter : AuthorizationFilterAttribute {

		private readonly Uri m_authenticationServerEndpoint;
		private readonly ILog m_log;

		public AuthenticationFilter(
			Uri authenticationServerEndpoint,
			ILogProvider logProvider = null
			) {

			m_authenticationServerEndpoint = authenticationServerEndpoint;
			
			// TODO: Create component to do auth

			logProvider = logProvider ?? NullLogProvider.Instance;
			m_log = logProvider.Get( GetType().Name );
		}

		public override void OnAuthorization( HttpActionContext actionContext ) {

			try {
				Authorize( actionContext );
			} catch( Exception ex ) {

				m_log.Error( "Authorization failed", ex );
				actionContext.Response = actionContext.Request.CreateResponse( HttpStatusCode.Unauthorized );
			}

			base.OnAuthorization( actionContext );
		}

		private void Authorize( HttpActionContext actionContext ) {

			// TODO: Call new library
			string jwtToken = null; // GetJwtToken( actionContext.Request );

			//Thread.CurrentPrincipal = m_authTokenValidator.VerifyAndDecode( jwtToken );
		}
	}
}
