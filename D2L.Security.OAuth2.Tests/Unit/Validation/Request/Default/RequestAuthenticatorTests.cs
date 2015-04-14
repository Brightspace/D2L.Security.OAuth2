using System;
using System.Net.Http;
using D2L.Security.OAuth2.Tests.Mocks;
using D2L.Security.OAuth2.Validation;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using D2L.Security.OAuth2.Validation.Token;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Request.Default {
	
	[TestFixture]
	[Category( "Unit" )]
	public class RequestAuthenticatorTests {

		[Test]
		public void Test1() {
			RunTest(
				request_xsrfHeader: "xsrf",
				request_authorizationHeader: RequestValidationConstants.BearerTokens.SCHEME_PREFIX + "mommabear",
				request_d2lApiCookie: null,
				accessToken_xsrfClaim: "xsrf",
				accessToken_validationStatus: ValidationStatus.Success,
				authenticationMode: AuthenticationMode.Full,
 				expected_authenticationStatus: AuthenticationStatus.Success
			);
		}

		private async void RunTest(
			string request_xsrfHeader,
			string request_d2lApiCookie,
			string request_authorizationHeader,
			string accessToken_xsrfClaim,
			ValidationStatus accessToken_validationStatus,
			AuthenticationMode authenticationMode,
			AuthenticationStatus expected_authenticationStatus
		) {
			
			IValidatedToken token = ValidatedTokenMock.Create(
				xsrfClaim: accessToken_xsrfClaim
			).Object;

			var validationResponse = new ValidationResponse(
				accessToken_validationStatus,
				token
			);

			IAccessTokenValidator tokenValidator = AccessTokenValidatorMock.Create(
				validationResponse
			).Object;

			IRequestAuthenticator authenticator = new RequestAuthenticator( tokenValidator );

			var httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( request_authorizationHeader )
				.WithXsrfHeader( request_xsrfHeader )
				.WithCookie( request_d2lApiCookie );

			AuthenticationResponse authResponse = await authenticator.AuthenticateAsync(
				new Uri( "https://somewhere.something" ), 
				httpRequestMessage
			).ConfigureAwait( false );

			Assert.AreEqual( expected_authenticationStatus, authResponse.Status );

		}

	}
}
