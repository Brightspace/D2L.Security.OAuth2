using System;
using System.Linq;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Remote;
using D2L.Security.OAuth2.Keys.Remote.Data;
using D2L.Security.OAuth2.Validation.Exceptions;

using Moq;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Keys.Remote {

	[TestFixture]
	[Category( "Unit" )]
	public class PublicKeyProviderTests {

		private static readonly Guid KEY_ID_1 = Guid.NewGuid();
		private static readonly Guid KEY_ID_2 = Guid.NewGuid();
		private const string KTY = "RSA";
		private const string BAD_KTY = "BAD";

		private readonly string JWKS_JSON_KEY1 = "{\"keys\":[{\"kty\":\"" + KTY + "\",\"use\":\"sig\",\"kid\":\"" + KEY_ID_1 + "\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n-O5HTvVDsTbqT34sJgJPG_BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0_UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf_XnTySbTJvgnRHDjyDJz6rWZzdmdNhM_aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW_r5432JcY7QKmUbIk8P-ZFm8quQk9jUad0V4Qia77qtn46P_vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf_NpTGBNquQ\",\"thing\":[1,2,3]}]}";
		private readonly string JWKS_JSON_KEY1_BADKTY = "{\"keys\":[{\"kty\":\"" + BAD_KTY + "\",\"use\":\"sig\",\"kid\":\"" + KEY_ID_1 + "\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n-O5HTvVDsTbqT34sJgJPG_BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0_UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf_XnTySbTJvgnRHDjyDJz6rWZzdmdNhM_aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW_r5432JcY7QKmUbIk8P-ZFm8quQk9jUad0V4Qia77qtn46P_vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf_NpTGBNquQ\"}]}";
		private readonly string JWKS_JSON_KEY2 = "{\"keys\":[{\"kty\":\"" + KTY + "\",\"use\":\"sig\",\"kid\":\"" + KEY_ID_2 + "\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n-O5HTvVDsTbqT34sJgJPG_BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0_UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf_XnTySbTJvgnRHDjyDJz6rWZzdmdNhM_aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW_r5432JcY7QKmUbIk8P-ZFm8quQk9jUad0V4Qia77qtn46P_vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf_NpTGBNquQ\"}]}";
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
		[ExpectedException( typeof( JsonWebKeyParseException ) )]
		public async Task KeyHasBadKeyType() {

			await RunTest(
				keyId: KEY_ID_1,
				jwksJsonFirstCall: JWKS_JSON_KEY1_BADKTY,
				firstCallWasFromCache: true,
				expected_callJwksProviderTwice: false
			).SafeAsync();

		}
		
		[Test]
		[ExpectedException( typeof( JsonWebKeyParseException ) )]
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
			Guid keyId,
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
			D2LSecurityToken token = await publicKeyProvider.GetSecurityTokenAsync( m_uri, keyId ).SafeAsync();
			
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
			Assert.AreEqual( keyId, token.KeyId );
		}

	}
}
