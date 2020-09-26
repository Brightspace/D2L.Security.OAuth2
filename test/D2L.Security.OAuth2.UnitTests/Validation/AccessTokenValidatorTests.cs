using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.TestUtilities;
using D2L.Security.OAuth2.TestUtilities.Mocks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;
using Moq;
using NUnit.Framework;
using Microsoft.IdentityModel.Logging;

namespace D2L.Security.OAuth2.Validation {
	[TestFixture]
	public class AccessTokenValidatorTests {
		private readonly Uri m_jwksEndpoint = new Uri( "http://someplace.somewhere" );

		[Test]
		public void ValidateAsync_GarbageJwt_Throws() {
			var publicKeyProvider = new Mock<IPublicKeyProvider>( MockBehavior.Strict ).Object;
			IAccessTokenValidator accessTokenValidator = new AccessTokenValidator( publicKeyProvider );

			Assert.Throws<ValidationException>( () =>
				accessTokenValidator.ValidateAsync( "garbage" ).ConfigureAwait( false ).GetAwaiter().GetResult()
			);
		}

		[Test]
		public async Task UnsignedJwt() {
			await RunTest(
				signJwt: false,
				jwtExpiry: DateTime.UtcNow.AddSeconds( 10 ),
				expectedExceptionType: typeof( InvalidTokenException )
			).ConfigureAwait( false );
		}

		[Test]
		public async Task ExpiredJwt() {
			IdentityModelEventSource.ShowPII = true;
			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddSeconds( -301 ),
				expectedExceptionType: typeof( ExpiredTokenException )
			).ConfigureAwait( false );
		}

		[Test]
		public async Task VeryExpiredJwt() {
			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddMonths( -2 ),
				expectedExceptionType: typeof( ExpiredTokenException )
			).ConfigureAwait( false );
		}

		[Test]
		[Description( "Jwt expiry will not be triggered until the token is at least 5 minutes past its expiry" )]
		public async Task ExpiredJwt_ButWithinGracePeriod() {
			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddSeconds( -295 )
			).ConfigureAwait( false );
		}

		[Test]
		public async Task SuccessCase() {
			await RunTest(
				signJwt: true,
				jwtExpiry: DateTime.UtcNow.AddSeconds( 10 )
			).ConfigureAwait( false );
		}

		private async Task RunTest(
			bool signJwt,
			DateTime jwtExpiry,
			Type expectedExceptionType = null
		) {
			string keyId = Guid.NewGuid().ToString();
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

			IAccessToken accessToken = null;
			Exception exception = null;
			try {
				accessToken = await tokenValidator.ValidateAsync(
					accessToken: serializedJwt
				).ConfigureAwait( false );
			} catch( Exception e ) {
				exception = e;
			}

			if( expectedExceptionType != null ) {
				Assert.IsNull( accessToken, "Unexpected access token returned from validation" );
				Assert.IsNotNull( exception, "Expected an exception but got null" );
				Assert.AreEqual( expectedExceptionType, exception.GetType(), "Wrong exception type" );
			} else {
				Assert.IsNotNull( accessToken, "Expected an access token but got none" );
			}
		}
	}
}
