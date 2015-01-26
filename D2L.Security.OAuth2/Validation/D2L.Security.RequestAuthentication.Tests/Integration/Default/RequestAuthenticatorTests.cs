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

		[Test]
		public void AuthenticateAndExtract_HttpRequestMessage_ExtractsComponentsProperly() {
			string cookieValue = "dummyjwt";
			string xsrfValue = "dummyxsrf";
			string bearerTokenValue = "dummybearertoken";

			HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
			RequestBuilder.AddAuthHeader( httpRequestMessage, bearerTokenValue );
			RequestBuilder.AddXsrfHeader( httpRequestMessage, xsrfValue );
			RequestBuilder.AddCookie( httpRequestMessage, cookieValue );

			IGenericPrincipal claims = new Mock<IGenericPrincipal>().Object;
			Mock<IAuthTokenValidator> validatorMock = new Mock<IAuthTokenValidator>();
			validatorMock.Setup( x => x.VerifyAndDecode( It.IsAny<string>(), out claims ) )
				.Returns( ValidationResult.Success );

			Mock<ICoreAuthenticator> coreAuthenticatorMock = new Mock<ICoreAuthenticator>();
			IRequestAuthenticator authenticator = new RequestAuthenticator( coreAuthenticatorMock.Object );

			ID2LPrincipal principal;
			AuthenticationResult result = authenticator.AuthenticateAndExtract( httpRequestMessage, out principal );

			Assert.AreEqual( AuthenticationResult.Success, result );
			coreAuthenticatorMock.Verify( x => x.Authenticate(
				cookieValue,
				xsrfValue,
				bearerTokenValue,
				out principal
				), Times.Once
				);
		}

		[Test]
		public void AuthenticateAndExtract_HttpRequest_ExtractsComponentsProperly() {
			string cookieValue = "dummyjwt";
			string xsrfValue = "dummyxsrf";
			string bearerTokenValue = "dummybearertoken";

			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null );
			RequestBuilder.AddCookie( httpRequest, cookieValue );
			RequestBuilder.AddAuthHeader( httpRequest, "Bearer " + bearerTokenValue );
			RequestBuilder.AddXsrfHeader( httpRequest, xsrfValue );

			IGenericPrincipal claims = new Mock<IGenericPrincipal>().Object;
			Mock<IAuthTokenValidator> validatorMock = new Mock<IAuthTokenValidator>();
			validatorMock.Setup( x => x.VerifyAndDecode( It.IsAny<string>(), out claims ) )
				.Returns( ValidationResult.Success );

			Mock<ICoreAuthenticator> coreAuthenticatorMock = new Mock<ICoreAuthenticator>();
			IRequestAuthenticator authenticator = new RequestAuthenticator( coreAuthenticatorMock.Object );

			ID2LPrincipal principal;
			AuthenticationResult result = authenticator.AuthenticateAndExtract( httpRequest, out principal );

			Assert.AreEqual( AuthenticationResult.Success, result );
			coreAuthenticatorMock.Verify( x => x.Authenticate(
				cookieValue,
				xsrfValue,
				bearerTokenValue,
				out principal
				), Times.Once
				);
		}
	}
}
