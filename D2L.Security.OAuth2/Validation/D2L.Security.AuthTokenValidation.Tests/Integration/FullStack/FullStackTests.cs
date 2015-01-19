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

		[Ignore( "Implement only if the HttpContext-based overload is kept." )]
		[Test]
		public void IAuthTokenValidator_VerifyAndDecode_HttpContext_Success() {
			Assert.Inconclusive();
		}
	}
}
