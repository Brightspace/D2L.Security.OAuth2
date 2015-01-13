using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		[Test]
		public void Validate_Success() {

			string jwt = AuthServerInvoker.AuthenticateAndGetJWT(
				LOReSManager.CLIENT_ID,
				LOReSManager.SECRET,
				LOReSScopes.MANAGE
				);

			IJWTValidator validator = JWTValidatorFactory.Create( AuthServerInvoker.AUTH_SERVER );
			IClaimsPrincipal claimsPrincipal = validator.Validate( jwt );

			Assert.IsTrue(
				ContainsScopeValue( claimsPrincipal, LOReSScopes.MANAGE )
				);
		}

		private bool ContainsScopeValue( IClaimsPrincipal claimsPrincipal, string scopeValue ) {
			string scopeValueFromClaim = claimsPrincipal.Claims.Where( x => x.Type == "scope" ).First().Value;
			return scopeValue == scopeValueFromClaim;
		}
	}
}
