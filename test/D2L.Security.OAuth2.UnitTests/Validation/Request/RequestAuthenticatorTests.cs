using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.TestUtilities;
using D2L.Security.OAuth2.TestUtilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request {
	[TestFixture]
	public class RequestAuthenticatorTests {
		private const string ACCESS_TOKEN = "some token";
		
		[Test]
		public async Task TokenInHeader_SuccessCase() {
			await RunTest(
				request_authorizationHeader: ACCESS_TOKEN
			).SafeAsync();
		}

		[Test]
		public async Task NoToken() {
			await RunTest(
				request_authorizationHeader: string.Empty,
				expectedExceptionType: null,
				expected_principalType: PrincipalType.Anonymous
			).SafeAsync();
		}
		
		[Test]
		public async Task TokenExpired() {
			await RunTest(
				request_authorizationHeader: ACCESS_TOKEN,
				expectedExceptionType: typeof( ExpiredTokenException )
			).SafeAsync();
		}

		private async Task RunTest(
			string request_authorizationHeader,
			Type expectedExceptionType = null,
			PrincipalType? expected_principalType = null
		) {
			IAccessToken token = AccessTokenMock.Create().Object;

			IAccessTokenValidator tokenValidator = AccessTokenValidatorMock.Create(
				accessToken: ACCESS_TOKEN,
				accessTokenAfterValidation: token,
				expectedExceptionType: expectedExceptionType
			).Object;

			IRequestAuthenticator authenticator = new RequestAuthenticator( tokenValidator );

			var httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( request_authorizationHeader );

			ID2LPrincipal principal = null;
			Exception exception = null;
			try {
				principal = await authenticator.AuthenticateAsync(
					httpRequestMessage
					).SafeAsync();
			} catch( Exception e ) {
				exception = e;
			}
			
			CheckExpectations(
				principal,
				exception,
				expectedExceptionType,
				expected_principalType );

			exception = null;

			HttpRequest httpRequest = RequestBuilder
				.Create()
				.WithAuthHeader( request_authorizationHeader );

			try {
				principal = await authenticator.AuthenticateAsync(
					httpRequest
				).SafeAsync();
			} catch( Exception e ) {
				exception = e;
			}
			
			CheckExpectations(
				principal,
				exception,
				expectedExceptionType,
				expected_principalType );
		}

		private void CheckExpectations(
			ID2LPrincipal principal,
			Exception exception,
			Type expectedExceptionType,
			PrincipalType? expected_principalType
		) {
			if( expectedExceptionType != null ) {
				Assert.IsNull( principal );
				Assert.IsNotNull( exception );
				Assert.AreEqual( expectedExceptionType, exception.GetType() );
				return;
			}

			Assert.IsNotNull( principal );
			Assert.IsNull( exception );

			if( expected_principalType.HasValue ) {
				Assert.AreEqual( expected_principalType, principal.Type );
			}
		}
	}
}