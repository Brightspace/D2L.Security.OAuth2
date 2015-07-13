using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Dispatcher;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.WebApiAuth.Principal;
using SimpleLogInterface;

namespace D2L.Security.WebApiAuth.Handler {
	
	internal sealed class AuthenticationMessageHandler : DelegatingHandler {

		private readonly IRequestAuthenticator m_requestAuthenticator;
		private readonly ILog m_log;
		private readonly AuthenticationMode m_authenticationMode;
		private readonly HttpClient m_httpClient;

		private bool m_isDisposed = false;

		public AuthenticationMessageHandler(
			HttpConfiguration httpConfiguration,
			Uri authenticationEndpoint,
			bool verifyCsrf,
			ILogProvider logProvider
			) {

			InnerHandler = new HttpControllerDispatcher( httpConfiguration );
			m_authenticationMode = verifyCsrf ? AuthenticationMode.Full : AuthenticationMode.SkipXsrfValidation;

			m_httpClient = new HttpClient();
			IAccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory.CreateRemoteValidator(
				m_httpClient,
				authenticationEndpoint
				);

			m_requestAuthenticator = RequestAuthenticatorFactory.Create( accessTokenValidator );

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

		/// <summary>
		/// See https://msdn.microsoft.com/en-us/library/b1yfkh5e(v=VS.100).aspx 
		/// (MSDN patterns for dealing with disposables; covers derived class scenarios.
		/// This is relevant because we're also inheriting from a disposable base class.)
		/// </summary>
		protected override void Dispose( bool disposing ) {
			if( !m_isDisposed ) {
				if( disposing ) {
					m_httpClient.Dispose();
				}
				
				m_isDisposed = true;
			}
			base.Dispose( disposing );
		}

		private void Authenticate( HttpRequestMessage request ) {
			AuthenticationResponse response = m_requestAuthenticator.AuthenticateAsync(
				request,
				m_authenticationMode
				).Result;

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
