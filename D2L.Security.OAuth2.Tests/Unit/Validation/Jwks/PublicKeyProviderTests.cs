using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI.WebControls;
using D2L.Security.OAuth2.Tests.Mocks;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Security.OAuth2.Validation.Jwks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using FluentAssertions;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.Jwks {

	[TestFixture]
	[Category( "Unit" )]
	public class PublicKeyProviderTests {
		
		private const string KEY_ID_1 = "KEY1";
		private const string KEY_ID_2 = "KEY2";
		private const string KTY = PublicKeyProvider.ALLOWED_KEY_TYPE;
		private const string BAD_KTY = "BAD";

		private const string JWKS_JSON_KEY1 = "{\"keys\":[{\"kty\":\"" + KTY + "\",\"use\":\"sig\",\"kid\":\"" + KEY_ID_1 + "\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n-O5HTvVDsTbqT34sJgJPG_BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0_UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf_XnTySbTJvgnRHDjyDJz6rWZzdmdNhM_aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW_r5432JcY7QKmUbIk8P-ZFm8quQk9jUad0V4Qia77qtn46P_vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf_NpTGBNquQ\",\"x5c\":[\"MIIC/DCCAeigAwIBAgIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDAeFw0xNDA4MDEyMTM0NTFaFw0yMDAxMDEwNDAwMDBaMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/juR071Q7E26k9+LCYCTxvwbrxPN2qnOAoQihU0HK8KMiVWfU9lyVIwHUrjS3e6n++/OKxgZnsR1paFnKbNRNP1HDq+RtBEBaSPYV5HrkD11SdzSU5Z1tWp/FVuZ15Utm+TzArkz3/1508km0yb4J0Rw48gyc+q1mc3ZnTYTP2jK9a1xN9xXDOxciiedZVyuLCdhA3at/VGZGo1v6+eN9iXGO0CplGyJPD/mRZvKrkJPY1GndFeEImu+6rZ+Oj/76PQTCz6L3D2WOOYZkK1LdC9IMCYgV3YmyBHewiu1WsmBtwl27LMUvJIeuU8xtVFXIS4bWOvO4cX/zaUxgTarkCAwEAAaNMMEowSAYDVR0BBEEwP4AQ8ZbpvXP8fwuZdg1earlZE6EZMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybIIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAA4IBAQBIfvG38kIhQ8Jjy24cVLmLxtmpEEBbgfODSkG4aGFctA+BDpxP1anjY/nYedssFcaDuFHNvJqNqL1vx2YpSST10UyjzD+TnfXPl+ssgpxDcBIeiS5Q0T5AdmFkJVUER5KAHxB3NuPitqODNKMW5I7dCQ2wM9cmttS6JkfrTjCv/SkSEXh9GYBItGqIk1n1Mbkx8nTEc4OSTHau01ofWx+d6+lvEKkIu5Blw3ZmWnLIGfWY+JQtFe8ldfgXHWCh3+wdaDdKhSB3ZLLdfz7zO3Cfg4L+/DFzkK0wLny/jF9yGfqqXv931L7gt75kGrIqXL28C5xErXUa5KPVFqN4xQKU\"]}]}";
		private const string JWKS_JSON_KEY1_BADKTY = "{\"keys\":[{\"kty\":\"" + BAD_KTY + "\",\"use\":\"sig\",\"kid\":\"" + KEY_ID_1 + "\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n-O5HTvVDsTbqT34sJgJPG_BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0_UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf_XnTySbTJvgnRHDjyDJz6rWZzdmdNhM_aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW_r5432JcY7QKmUbIk8P-ZFm8quQk9jUad0V4Qia77qtn46P_vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf_NpTGBNquQ\",\"x5c\":[\"MIIC/DCCAeigAwIBAgIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDAeFw0xNDA4MDEyMTM0NTFaFw0yMDAxMDEwNDAwMDBaMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/juR071Q7E26k9+LCYCTxvwbrxPN2qnOAoQihU0HK8KMiVWfU9lyVIwHUrjS3e6n++/OKxgZnsR1paFnKbNRNP1HDq+RtBEBaSPYV5HrkD11SdzSU5Z1tWp/FVuZ15Utm+TzArkz3/1508km0yb4J0Rw48gyc+q1mc3ZnTYTP2jK9a1xN9xXDOxciiedZVyuLCdhA3at/VGZGo1v6+eN9iXGO0CplGyJPD/mRZvKrkJPY1GndFeEImu+6rZ+Oj/76PQTCz6L3D2WOOYZkK1LdC9IMCYgV3YmyBHewiu1WsmBtwl27LMUvJIeuU8xtVFXIS4bWOvO4cX/zaUxgTarkCAwEAAaNMMEowSAYDVR0BBEEwP4AQ8ZbpvXP8fwuZdg1earlZE6EZMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybIIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAA4IBAQBIfvG38kIhQ8Jjy24cVLmLxtmpEEBbgfODSkG4aGFctA+BDpxP1anjY/nYedssFcaDuFHNvJqNqL1vx2YpSST10UyjzD+TnfXPl+ssgpxDcBIeiS5Q0T5AdmFkJVUER5KAHxB3NuPitqODNKMW5I7dCQ2wM9cmttS6JkfrTjCv/SkSEXh9GYBItGqIk1n1Mbkx8nTEc4OSTHau01ofWx+d6+lvEKkIu5Blw3ZmWnLIGfWY+JQtFe8ldfgXHWCh3+wdaDdKhSB3ZLLdfz7zO3Cfg4L+/DFzkK0wLny/jF9yGfqqXv931L7gt75kGrIqXL28C5xErXUa5KPVFqN4xQKU\"]}]}";
		private const string JWKS_JSON_KEY2 = "{\"keys\":[{\"kty\":\"" + KTY + "\",\"use\":\"sig\",\"kid\":\"" + KEY_ID_2 + "\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n-O5HTvVDsTbqT34sJgJPG_BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0_UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf_XnTySbTJvgnRHDjyDJz6rWZzdmdNhM_aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW_r5432JcY7QKmUbIk8P-ZFm8quQk9jUad0V4Qia77qtn46P_vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf_NpTGBNquQ\",\"x5c\":[\"MIIC/DCCAeigAwIBAgIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDAeFw0xNDA4MDEyMTM0NTFaFw0yMDAxMDEwNDAwMDBaMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/juR071Q7E26k9+LCYCTxvwbrxPN2qnOAoQihU0HK8KMiVWfU9lyVIwHUrjS3e6n++/OKxgZnsR1paFnKbNRNP1HDq+RtBEBaSPYV5HrkD11SdzSU5Z1tWp/FVuZ15Utm+TzArkz3/1508km0yb4J0Rw48gyc+q1mc3ZnTYTP2jK9a1xN9xXDOxciiedZVyuLCdhA3at/VGZGo1v6+eN9iXGO0CplGyJPD/mRZvKrkJPY1GndFeEImu+6rZ+Oj/76PQTCz6L3D2WOOYZkK1LdC9IMCYgV3YmyBHewiu1WsmBtwl27LMUvJIeuU8xtVFXIS4bWOvO4cX/zaUxgTarkCAwEAAaNMMEowSAYDVR0BBEEwP4AQ8ZbpvXP8fwuZdg1earlZE6EZMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybIIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAA4IBAQBIfvG38kIhQ8Jjy24cVLmLxtmpEEBbgfODSkG4aGFctA+BDpxP1anjY/nYedssFcaDuFHNvJqNqL1vx2YpSST10UyjzD+TnfXPl+ssgpxDcBIeiS5Q0T5AdmFkJVUER5KAHxB3NuPitqODNKMW5I7dCQ2wM9cmttS6JkfrTjCv/SkSEXh9GYBItGqIk1n1Mbkx8nTEc4OSTHau01ofWx+d6+lvEKkIu5Blw3ZmWnLIGfWY+JQtFe8ldfgXHWCh3+wdaDdKhSB3ZLLdfz7zO3Cfg4L+/DFzkK0wLny/jF9yGfqqXv931L7gt75kGrIqXL28C5xErXUa5KPVFqN4xQKU\"]}]}";
		private const string JWKS_JSON_INCORRECTFORMAT = "{\"keys\":0}";
		private const string JWKS_JSON_MALFORMED = "fddffdfddfs";

		private readonly Uri m_uri = new Uri( "http://somewhere.someplace" );

		[Test]
		public async Task KeyExistsInCache() {

			await RunTest(
				keyId: KEY_ID_1,
				jwksJsonFirstCall: JWKS_JSON_KEY1,
				firstCallWasFromCache: true,
				expected_callJwksProviderTwice: false
			).SafeAsync();

		}
		
		[Test( Description = "The JWKS is in the cache, but the key asked for isn't there.  The second (non cached) call gets the set with the key we need." )]
		public async Task JwksKeyNotInCache_HardRefreshFindsKey() {

			await RunTest(
				keyId: KEY_ID_2,
				jwksJsonFirstCall: JWKS_JSON_KEY1,
				firstCallWasFromCache: true,
				jwksJsonSecondCall: JWKS_JSON_KEY2,
				expected_callJwksProviderTwice: true
			).SafeAsync();

		}
		
		[Test]
		[ExpectedException( typeof( PublicKeyNotFoundException ) )]
		public async Task KeyNotInCache_And_KeyDoesNotExist() {

			await RunTest(
				keyId: KEY_ID_1,
				jwksJsonFirstCall: JWKS_JSON_KEY2,
				firstCallWasFromCache: false,
				expected_callJwksProviderTwice: false
			).SafeAsync();

		}

		[Test]
		[ExpectedException( typeof( InvalidKeyTypeException ) )]
		public async Task KeyHasBadKeyType() {

			await RunTest(
				keyId: KEY_ID_1,
				jwksJsonFirstCall: JWKS_JSON_KEY1_BADKTY,
				firstCallWasFromCache: true,
				expected_callJwksProviderTwice: false
			).SafeAsync();

		}
		
		[Test]
		[ExpectedException( typeof( PublicKeyNotFoundException ) )]
		public async Task IncorrectJwksFormat() {

			await RunTest(
				keyId: KEY_ID_1,
				jwksJsonFirstCall: JWKS_JSON_INCORRECTFORMAT,
				firstCallWasFromCache: false,
				expected_callJwksProviderTwice: false
			).SafeAsync();

		}

		[Test]
		[ExpectedException( typeof( ArgumentException ) )]
		public async Task MalformedJwks() {

			await RunTest(
				keyId: KEY_ID_1,
				jwksJsonFirstCall: JWKS_JSON_MALFORMED,
				firstCallWasFromCache: false,
				expected_callJwksProviderTwice: false
			).SafeAsync();

		}
		
		private async Task RunTest(
			string keyId,
			string jwksJsonFirstCall,
			bool firstCallWasFromCache,
			string jwksJsonSecondCall = null,
			bool expected_callJwksProviderTwice = false
		) {

			const bool skipCacheFirstCall = false;
			const bool skipCacheSecondCall = true;

			var jwksResponseFirstCall = new JwksResponse(
				fromCache: firstCallWasFromCache,
				jwksJson: jwksJsonFirstCall
			);

			var jwksResponseSecondCall = new JwksResponse(
				fromCache: false,
				jwksJson: jwksJsonSecondCall
			);
			
			var jwksProviderMock = new Mock<IJwksProvider>();

			jwksProviderMock.Setup(
				p => p.RequestJwksAsync(
					m_uri,
					skipCacheFirstCall
				)
			).Returns( Task.FromResult( jwksResponseFirstCall ) );
			
			jwksProviderMock.Setup(
				p => p.RequestJwksAsync(
					m_uri,
					skipCacheSecondCall
				)
			).Returns( Task.FromResult( jwksResponseSecondCall ) );
			
			IPublicKeyProvider publicKeyProvider = new PublicKeyProvider( jwksProviderMock.Object );
			SecurityToken token = await publicKeyProvider.GetSecurityTokenAsync( m_uri, keyId ).SafeAsync();
			
			jwksProviderMock.Verify(
				p => p.RequestJwksAsync(
					m_uri,
					skipCacheFirstCall
				),
				Times.Once()
			);

			Times secondCallTimes = expected_callJwksProviderTwice ? Times.Once() : Times.Never();

			jwksProviderMock.Verify(
				p => p.RequestJwksAsync(
					m_uri,
					skipCacheSecondCall
				),
				secondCallTimes
			);
			
			Assert.AreEqual( 1, token.SecurityKeys.Count() );
			Assert.AreEqual( keyId, token.Id );
		}

	}
}
