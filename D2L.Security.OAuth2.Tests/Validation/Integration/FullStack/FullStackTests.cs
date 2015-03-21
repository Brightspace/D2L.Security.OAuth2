using D2L.Security.OAuth2.Validation.Token.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Token.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		[Test]
		public void IAuthTokenValidator_VerifyAndDecode_Success() {
			string expectedScope = TestCredentials.LOReSScopes.MANAGE;

			string jwt = AuthServerInvoker.AuthenticateAndGetJwt(
				TestCredentials.LOReSManager.CLIENT_ID,
				TestCredentials.LOReSManager.SECRET,
				expectedScope
				);

			IAuthTokenValidator validator = AuthTokenValidatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI
				);

			IValidatedToken validatedToken;
			Assert.AreEqual( ValidationResult.Success, validator.VerifyAndDecode( jwt, out validatedToken ) );
			Assertions.ScopeClaimsCountIsExactly( validatedToken, 1 );
			Assertions.ContainsScopeValue( validatedToken, expectedScope );
		}

		[Test]
		public void IAuthTokenValidator_VerifyAndDecode_BadJwt_Failure() {
			
			IAuthTokenValidator validator = AuthTokenValidatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI
				);

			IValidatedToken validatedToken;
			Assertions.Throws( () => validator.VerifyAndDecode( "dummyjwt", out validatedToken ) );
		}
	}
}
