using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Dispatcher;
using D2L.Security.RequestAuthentication;
using D2L.Security.WebApiAuth.Principal.Default;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuth.Handler {
	
	internal sealed class AuthenticationMessageHandler : DelegatingHandler {

		private readonly IRequestAuthenticator m_requestAuthenticator;
		private readonly ILog m_log;

		public AuthenticationMessageHandler(
			HttpConfiguration httpConfiguration,
			Uri authenticationEndpoint,
			bool verifyCsrf,
			ILogProvider logProvider
			) {

			InnerHandler = new HttpControllerDispatcher( httpConfiguration );
			Mode mode = verifyCsrf ? Mode.Full : Mode.SkipXsrfValidation;
			m_requestAuthenticator = RequestAuthenticatorFactory.Create( authenticationEndpoint, mode );
			m_log = logProvider.Get( typeof( AuthenticationMessageHandler ) );
		}

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request,
			CancellationToken cancellationToken
			) {

			try {
				Authorize( request );
			} catch( AuthenticationException ex ) {
				m_log.Warn( "Authentication failed", ex );
				return Task.FromResult( request.CreateResponse( HttpStatusCode.Unauthorized ) );
			} catch( Exception ex ) {
				m_log.Error( "An unknown error occurred during authentication", ex );
				return Task.FromResult( request.CreateResponse( HttpStatusCode.Unauthorized ) );
			}

			return base.SendAsync( request, cancellationToken );
		}

		private void Authorize( HttpRequestMessage request ) {

			ID2LPrincipal principal;

			AuthenticationResult result =
				m_requestAuthenticator.AuthenticateAndExtract(
					request,
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
