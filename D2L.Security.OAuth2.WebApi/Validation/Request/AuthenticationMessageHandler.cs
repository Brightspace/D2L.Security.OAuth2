using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Dispatcher;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Security.OAuth2.Validation.Request;
using SimpleLogInterface;

namespace D2L.Security.OAuth2.Validation.Request {
	
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

		protected override async Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request,
			CancellationToken cancellationToken
			) {

			try {
				AuthenticateAsync( request );
			} catch( ValidationException ex ) {
				m_log.Warn( "Authentication failed", ex );
				return request.CreateResponse( HttpStatusCode.Unauthorized );
			} catch( Exception ex ) {
				m_log.Error( "An unknown error occurred during authentication", ex );
				return request.CreateResponse( HttpStatusCode.Unauthorized );
			}

			return await base.SendAsync( request, cancellationToken )
				.ConfigureAwait( false );
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

		private void AuthenticateAsync( HttpRequestMessage request ) {
			var principal = m_requestAuthenticator.AuthenticateAsync(
				   request,
				   m_authenticationMode
			   ).ConfigureAwait( false ).GetAwaiter().GetResult();

			Thread.CurrentPrincipal = new D2LPrincipalAdapter( principal );
		}
	}
}