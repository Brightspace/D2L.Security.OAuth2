using System;
using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Core;
using D2L.Security.RequestAuthentication.Default;

namespace D2L.Security.RequestAuthentication {
	public static class RequestAuthenticatorFactory {

		/// <summary>
		/// Creates a request authenticator which will perform full authentication of requests
		/// </summary>
		/// <param name="authServiceEndpoint">End point of the auth service</param>
		/// <returns>A request authenticator</returns>
		public static IRequestAuthenticator Create( Uri authServiceEndpoint ) {
			return Create( authServiceEndpoint, Mode.Full );
		}

		/// <summary>
		/// Creates a request authenticator which will function as dictated by the specified mode
		/// </summary>
		/// <param name="authServiceEndpoint">End point of the auth service</param>
		/// <param name="mode">The mode of the request authenticator</param>
		/// <returns>A request authenticator</returns>
		public static IRequestAuthenticator Create( Uri authServiceEndpoint, Mode mode ) {
			switch( mode ) {
				case Mode.Full:
					return CreateWorker( authServiceEndpoint, true );
				case Mode.SkipXsrfValidation:
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
