using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Dispatcher;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.WebApiAuth.Principal;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuth.Handler {
	
	internal sealed class AuthenticationMessageHandler : DelegatingHandler {

		private readonly IRequestAuthenticator m_requestAuthenticator;
		private readonly ILog m_log;
		private readonly AuthenticationMode m_authenticationMode;
		private readonly Uri m_authenticationEndpoint;

		public AuthenticationMessageHandler(
			HttpConfiguration httpConfiguration,
			Uri authenticationEndpoint,
			bool verifyCsrf,
			ILogProvider logProvider
			) {

			InnerHandler = new HttpControllerDispatcher( httpConfiguration );
			m_authenticationMode = verifyCsrf ? AuthenticationMode.Full : AuthenticationMode.SkipXsrfValidation;
			m_authenticationEndpoint = authenticationEndpoint;
			m_requestAuthenticator = RequestAuthenticatorFactory.Create();

			m_log = logProvider.Get( typeof( AuthenticationMessageHandler ) );
		}

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request,
			CancellationToken cancellationToken
			) {

			try {
				Authenticate( request );
			} catch( AuthenticationException ex ) {
				m_log.Warn( "Authentication failed", ex );
				return Task.FromResult( request.CreateResponse( HttpStatusCode.Unauthorized ) );
			} catch( Exception ex ) {
				m_log.Error( "An unknown error occurred during authentication", ex );
				return Task.FromResult( request.CreateResponse( HttpStatusCode.Unauthorized ) );
			}

			return base.SendAsync( request, cancellationToken );
		}

		private void Authenticate( HttpRequestMessage request ) {

			AuthenticationResponse response = m_requestAuthenticator.AuthenticateAsync(
				m_authenticationEndpoint,
				request,
				m_authenticationMode
				)
				.ConfigureAwait( false )
				.GetAwaiter()
				.GetResult();

			switch( response.Status ) {
				case AuthenticationStatus.Success:
					Thread.CurrentPrincipal = new D2LPrincipalAdapter( response.Principal );
					break;

				default:
					throw new AuthenticationException( string.Format( "Authentication failed: {0}", response.Status ) );
			}
		}
	}
}
