using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using D2L.Security.RequestAuthentication;
using D2L.Security.WebApiAuthFilter.Exceptions;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuthFilter {

	[AttributeUsage( AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false )]
	public sealed class AuthenticateAttribute : AuthorizationFilterAttribute {

		private readonly IRequestAuthenticator m_requestAuthenticator;
		private readonly ILog m_log;

		private bool m_verifyCsrf = true;

		public AuthenticateAttribute() {

			if ( AuthenticationConfig.AuthServiceEndpoint != null ) {
				m_requestAuthenticator = RequestAuthenticatorFactory.Create( AuthenticationConfig.AuthServiceEndpoint );
			} else {
				m_requestAuthenticator = NullRequestAuthenticator.Instance;
			}

			if( AuthenticationConfig.LogProvider == null ) {
				throw new InitializeNotCalledException( "Initialize method was not called prior to authentication filter being created" );
			}

			m_log = AuthenticationConfig.LogProvider.Get( typeof( AuthenticateAttribute ) );
		}

		public bool VerifyCsrf {
			get { return m_verifyCsrf; }
			set { m_verifyCsrf = value; }
		}

		public override void OnAuthorization( HttpActionContext actionContext ) {

			base.OnAuthorization( actionContext );

			try {
				Authorize( actionContext );
			} catch ( AuthenticationException ex ) {
				m_log.Warn( "Authentication failed", ex );
				actionContext.Response = actionContext.Request.CreateResponse( HttpStatusCode.Unauthorized );
			} catch( Exception ex ) {

				m_log.Error( "An unknown error occurred during authentication", ex );
				actionContext.Response = actionContext.Request.CreateResponse( HttpStatusCode.Unauthorized );
				throw;
			}
		}

		private void Authorize( HttpActionContext actionContext ) {

			ID2LPrincipal principal;

			AuthenticationResult result =
				m_requestAuthenticator.AuthenticateAndExtract(
					actionContext.Request,
					out principal
				);

			switch( result ) {
				case AuthenticationResult.Success:
					Thread.CurrentPrincipal = new D2LPrincipalAdapter();
					break;

				default:
					throw new AuthenticationException( string.Format( "Authentication failed: {0}", result ) );
			}
		}
	}
}
