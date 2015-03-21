using System;
using D2L.Security.OAuth2.Validation.Token;
using D2L.Security.OAuth2.Validation.Request.Core;
using D2L.Security.OAuth2.Validation.Request.Default;

namespace D2L.Security.OAuth2.Validation.Request {
	public static class RequestAuthenticatorFactory {

		/// <summary>
		/// Creates a request authenticator which will perform full authentication of requests
		/// </summary>
		/// <param name="authServiceEndpoint">End point of the auth service</param>
		/// <returns>A request authenticator</returns>
		public static IRequestAuthenticator Create( Uri authServiceEndpoint ) {
			return Create( authServiceEndpoint, AuthenticationMode.Full );
		}

		/// <summary>
		/// Creates a request authenticator which will function as dictated by the specified mode
		/// </summary>
		/// <param name="authServiceEndpoint">End point of the auth service</param>
		/// <param name="mode">The mode of the request authenticator</param>
		/// <returns>A request authenticator</returns>
		public static IRequestAuthenticator Create( Uri authServiceEndpoint, AuthenticationMode mode ) {
			switch( mode ) {
				case AuthenticationMode.Full:
					return CreateWorker( authServiceEndpoint, true );
				case AuthenticationMode.SkipXsrfValidation:
					return CreateWorker( authServiceEndpoint, false );
			}

			throw new ArgumentException( "Unsupported mode", "mode" );
		}

		private static IRequestAuthenticator CreateWorker( Uri authServiceEndpoint, bool mustValidateXsrf ) {
			IAuthTokenValidator tokenValidator = AuthTokenValidatorFactory.Create( authServiceEndpoint );
			ICoreAuthenticator coreAuthenticator = CoreAuthenticatorFactory.Create( tokenValidator, mustValidateXsrf );
			return new RequestAuthenticator( coreAuthenticator );
		}
	}
}
