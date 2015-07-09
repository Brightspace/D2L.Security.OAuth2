using System;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Tests.Utilities;
using D2L.Security.OAuth2.Tests.Utilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation {

	[TestFixture]
	[Category( "Unit" )]
	public class AccessTokenValidatorTests {

		private readonly Uri m_jwksEndpoint = new Uri( "http://someplace.somewhere" );

		[Test]
		[ExpectedException( typeof( InvalidSignatureAlgorithmException ) )]
		public async Task UnsignedJwt() {

			await RunTest(
				signJwt: false,
				jwtExpiry: DateTime.UtcNow.AddSeconds( 10 )
			).SafeAsync();
		}

		[Test]
		public async Task ExpiredJwt() {

			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddSeconds( -301 ),
				expected_validationStatus: ValidationStatus.Expired,
				expected_accessTokenNull: true
			).SafeAsync();
		}
		
		[Test]
		public async Task VeryExpiredJwt() {

			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddMonths( -2 ),
				expected_validationStatus: ValidationStatus.Expired,
				expected_accessTokenNull: true
			).SafeAsync();
		}

		[Test]
		[Description( "Jwt expiry will not be triggered until the token is at least 5 minutes past its expiry" )]
		public async Task ExpiredJwt_ButWithinGracePeriod() {

			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddSeconds( -295 ),
				expected_validationStatus: ValidationStatus.Success,
				expected_accessTokenNull: false
			).SafeAsync();
		}
		
		[Test]
		public async Task SuccessCase() {

			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddSeconds( 10 ),
				expected_validationStatus: ValidationStatus.Success,
				expected_accessTokenNull: false
			).SafeAsync();
		}
		
		private async Task RunTest(
			bool signJwt,
			DateTime jwtExpiry,
			ValidationStatus? expected_validationStatus = null,
			bool? expected_accessTokenNull = null
		) {

			Guid keyId = Guid.NewGuid();
			D2LSecurityToken signingToken = D2LSecurityTokenUtility.CreateActiveToken( id: keyId );
			SigningCredentials signingCredentials = null;
			if( signJwt ) {
				signingCredentials = signingToken.GetSigningCredentials();
			}

			var jwtToken = new JwtSecurityToken(
				issuer: "someissuer",
				signingCredentials: signingCredentials,
				expires: jwtExpiry
			);

			var tokenHandler = new JwtSecurityTokenHandler();
			string serializedJwt = tokenHandler.WriteToken( jwtToken );
			
			IPublicKeyProvider publicKeyProvider = PublicKeyProviderMock.Create(
				m_jwksEndpoint,
				keyId,
				signingToken
			).Object;

			IAccessTokenValidator tokenValidator = new AccessTokenValidator(
				publicKeyProvider
			);

			IValidationResponse response = await tokenValidator.ValidateAsync(
				accessToken: serializedJwt
			).SafeAsync();
			
			Assert.AreEqual( expected_validationStatus, response.Status );
			Assert.AreEqual( expected_accessTokenNull, response.AccessToken == null );

		}
		
	}
}
