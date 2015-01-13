using System.Linq;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		[Test]
		public void Validate_Success() {

			string expectedScope = TestCredentials.LOReSScopes.MANAGE;

			string jwt = AuthServerInvoker.AuthenticateAndGetJWT(
				TestCredentials.LOReSManager.CLIENT_ID,
				TestCredentials.LOReSManager.SECRET,
				expectedScope
				);

			IJWTValidator validator = JWTValidatorFactory.Create( TestUrls.TOKEN_VERIFICATION_AUTHORITY_URL );
			IValidatedJWT validatedJWT = validator.Validate( jwt );

			Assert.IsTrue(
				ContainsScopeValue( validatedJWT, expectedScope )
				);
		}

		private bool ContainsScopeValue( IValidatedJWT validatedJWT, string scopeValue ) {
			string scopeValueFromClaim = validatedJWT.Claims.First( x => x.Type == "scope" ).Value;
			return scopeValue == scopeValueFromClaim;
		}
	}
}
