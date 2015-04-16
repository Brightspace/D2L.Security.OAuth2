using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.Tests.Mocks;
using D2L.Security.OAuth2.Tests.SecurityTokens.Unit;
using D2L.Security.OAuth2.Validation;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Jwks;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation {
	
	[TestFixture]
	[Category( "Unit" )]
	public class AccessTokenValidatorTests {

		[Test]
		public void test() {
			
			//D2LSecurityToken token = Utilities.CreateActiveToken();
			
			IPublicKeyProvider publicKeyProvider = null;/* = PublicKeyProviderMock.Create(
				keyId: keyId,

			).Object;*/

			//publicKeyProvider.

			IAccessTokenValidator tokenValidator = new AccessTokenValidator(
				publicKeyProvider
			);

			//tokenValidator.ValidateAsync( );




		}

	}
}
