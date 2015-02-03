using System.Net.Http;
using System.Web;
using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Core;
using D2L.Security.RequestAuthentication.Default;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using Moq;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Integration.Default {
	
	[TestFixture]
	internal sealed class RequestAuthenticatorTests {

		private const string DUMMY_JWT = "dummyjwt";
		private const string DUMMY_XSRF = "dummyxsrf";
		private const string DUMMY_BEARER_TOKEN = "dummybearertoken";

		[Test]
		public void AuthenticateAndExtract_HttpRequestMessage_ExtractsComponentsProperly() {
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage()
				.WithAuthHeader( DUMMY_BEARER_TOKEN )
				.WithXsrfHeader( DUMMY_XSRF )
				.WithCookie( DUMMY_JWT );

			IValidatedToken claims = new Mock<IValidatedToken>().Object;
			Mock<IAuthTokenValidator> validatorMock = new Mock<IAuthTokenValidator>();
			validatorMock.Setup( x => x.VerifyAndDecode( It.IsAny<string>(), out claims ) )
				.Returns( ValidationResult.Success );

			Mock<ICoreAuthenticator> coreAuthenticatorMock = new Mock<ICoreAuthenticator>();
			IRequestAuthenticator authenticator = new RequestAuthenticator( coreAuthenticatorMock.Object );

			ID2LPrincipal principal;
			AuthenticationResult result = authenticator.AuthenticateAndExtract( httpRequestMessage, out principal );

			Assert.AreEqual( AuthenticationResult.Success, result );
			coreAuthenticatorMock.Verify( x => x.Authenticate(
				DUMMY_JWT,
				DUMMY_XSRF,
				DUMMY_BEARER_TOKEN,
				out principal
				), Times.Once
				);
		}

		[Test]
		public void AuthenticateAndExtract_HttpRequest_ExtractsComponentsProperly() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( DUMMY_JWT )
				.WithAuthHeader( DUMMY_BEARER_TOKEN )
				.WithXsrfHeader( DUMMY_XSRF );

			IValidatedToken claims = new Mock<IValidatedToken>().Object;
			Mock<IAuthTokenValidator> validatorMock = new Mock<IAuthTokenValidator>();
			validatorMock.Setup( x => x.VerifyAndDecode( It.IsAny<string>(), out claims ) )
				.Returns( ValidationResult.Success );

			Mock<ICoreAuthenticator> coreAuthenticatorMock = new Mock<ICoreAuthenticator>();
			IRequestAuthenticator authenticator = new RequestAuthenticator( coreAuthenticatorMock.Object );

			ID2LPrincipal principal;
			AuthenticationResult result = authenticator.AuthenticateAndExtract( httpRequest, out principal );

			Assert.AreEqual( AuthenticationResult.Success, result );
			coreAuthenticatorMock.Verify( x => x.Authenticate(
				DUMMY_JWT,
				DUMMY_XSRF,
				DUMMY_BEARER_TOKEN,
				out principal
				), Times.Once
				);
		}
	}
}
