using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Services;
using SimpleLogInterface;

namespace D2L.Security.OAuth2.Authentication {
	public sealed class OAuth2AuthenticationFilter : IAuthenticationFilter {
		private readonly ILog m_log;
		private readonly IRequestAuthenticator m_requestAuthenticator;
		private readonly Action<ID2LPrincipal> m_principalCallback;

		/// <summary>
		/// Authentication filter for Brightspace OAuth 2.0
		/// </summary>
		/// <param name="logProvider"></param>
		/// <param name="requestAuthenticator"></param>
		/// <param name="principalCallback">Callback that gets passed an ID2LPrincipal on every authentication. E.g. you can use this to register the principal for dependency injection.</param>
		public OAuth2AuthenticationFilter(
			ILogProvider logProvider,
			IRequestAuthenticator requestAuthenticator,
			Action<ID2LPrincipal> principalCallback
		) {
			m_log = logProvider.Get( this.GetType() );
			m_requestAuthenticator = requestAuthenticator;
			m_principalCallback = principalCallback;
		}

		async Task IAuthenticationFilter.AuthenticateAsync(
			HttpAuthenticationContext context,
			CancellationToken cancellationToken
		) {
			HttpRequestMessage request = context.Request;

			ID2LPrincipal principal;

			try {
				principal = await AuthenticateAsync( context ).SafeAsync();
			} catch( ValidationException e ) {
				m_log.Warn( "Authentication failed", e );
				context.ErrorResult = new AuthenticationFailureResult( e );
				return;
			} catch( Exception e ) {
				m_log.Error( "Unexpected exception during authentication", e );
				throw;
			}

			// Note: the principal at this point may be anonymous if no credentials
			// were sent. This can be guarded against with the authorization attributes
			// and is by DefaultStrictAuthorizationAttribute.

			// Add to request context so things that can't use DI (e.g. extension
			// methods) can get the principal.
			context.Principal = new D2LPrincipalToIPrincipalAdaptor( principal );

			// We're using a callback here to avoid coupling to Unity (for example)
			m_principalCallback( principal );
		}

		private async Task<ID2LPrincipal> AuthenticateAsync( HttpAuthenticationContext context ) {
			ID2LPrincipal principal = await m_requestAuthenticator
				.AuthenticateAsync( context.Request, AuthenticationMode.Full )
				.SafeAsync();

			return principal;
		}

		Task IAuthenticationFilter.ChallengeAsync( HttpAuthenticationChallengeContext context, CancellationToken cancellationToken ) {
			return TaskHelpers.CompletedTask;
		}

		bool IFilter.AllowMultiple {
			get { return false; }
		}
	}
}
