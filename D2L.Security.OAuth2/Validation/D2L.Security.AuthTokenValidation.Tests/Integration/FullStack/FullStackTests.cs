using System.Web;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		[Test]
		public void IAuthTokenValidator_VerifyAndDecode_Success() {
			string expectedScope = TestCredentials.LOReSScopes.MANAGE;

			string jwt = AuthServerInvoker.AuthenticateAndGetJWT(
				TestCredentials.LOReSManager.CLIENT_ID,
				TestCredentials.LOReSManager.SECRET,
				expectedScope
				);

			IAuthTokenValidator validator = AuthTokenValidatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI
				);

			IGenericPrincipal principal = validator.VerifyAndDecode( jwt );
			Assert.AreEqual( 1, principal.Scopes.Count );
			Assert.DoesNotThrow( () => principal.AssertScope( expectedScope ) );
		}

		[Test]
		public void IAuthTokenValidator_VerifyAndDecode_HttpContext_Cookie_Success() {
			string expectedScope = TestCredentials.LOReSScopes.MANAGE;

			string jwt = AuthServerInvoker.AuthenticateAndGetJWT(
				TestCredentials.LOReSManager.CLIENT_ID,
				TestCredentials.LOReSManager.SECRET,
				expectedScope
				);
			HttpRequest httpRequest = new HttpRequest( null, "http://localhost", null );
			httpRequest.Cookies.Add( new HttpCookie( "d2lApi", jwt ) );

			IAuthTokenValidator validator = AuthTokenValidatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI
				);

			IGenericPrincipal principal = validator.VerifyAndDecode( httpRequest );
			Assert.AreEqual( 1, principal.Scopes.Count );
			Assert.DoesNotThrow( () => principal.AssertScope( expectedScope ) );
		}

		[Test]
		public void IAuthTokenValidator_VerifyAndDecode_HttpContext_Header_Success() {
			string expectedScope = TestCredentials.LOReSScopes.MANAGE;

			string jwt = AuthServerInvoker.AuthenticateAndGetJWT(
				TestCredentials.LOReSManager.CLIENT_ID,
				TestCredentials.LOReSManager.SECRET,
				expectedScope
				);
			HttpRequest httpRequest = new HttpRequest( null, "http://localhost", null );
			HttpRequestBuilder.AddAuthHeader( httpRequest, string.Format( "Bearer {0}", jwt ) );

			IAuthTokenValidator validator = AuthTokenValidatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI
				);

			IGenericPrincipal principal = validator.VerifyAndDecode( httpRequest );
			Assert.AreEqual( 1, principal.Scopes.Count );
			Assert.DoesNotThrow( () => principal.AssertScope( expectedScope ) );
		}
	}
}
