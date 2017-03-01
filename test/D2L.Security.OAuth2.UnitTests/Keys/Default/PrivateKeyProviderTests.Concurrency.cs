using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Threading;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default {
	[TestFixture]
	internal sealed partial class PrivateKeyProviderTests {
		private const string TEST_ISSUER = "MyTestIssuer";
		private const int THREAD_COUNT = 32;
		private const int SIGNATURES_PER_THREAD = 10;

		[Explicit( "Long running" )]
		[Category( "ExcludeFromBuild" )]
		[TestCase( 100, 5 )]
		[TestCase( 100, 50 )]
		[TestCase( 500, 250 )]
		[TestCase( 500, 20 )]
		[TestCase( 2000, 1000 )]
		[TestCase( 2000, 50 )]
		public void GetSigningCredentialsAsync_HighLoad_FrequentlyRollingKeys_KeysRemainValid(
			int keyLifeTimeMilliseconds,
			int keyOverlapIntervalMilliseconds
		) {
			IPrivateKeyProvider provider = new RotatingPrivateKeyProvider(
				new RsaPrivateKeyProvider(
					new D2LSecurityTokenFactory(
						m_mockDateTimeProvider.Object,
						TimeSpan.FromMilliseconds( keyLifeTimeMilliseconds )
					)
				),
				m_mockDateTimeProvider.Object,
				TimeSpan.FromMilliseconds( keyOverlapIntervalMilliseconds )
			);

			IList<Thread> threads = new List<Thread>();
			ManualResetEventSlim go = new ManualResetEventSlim( false );

			for( int i = 0; i < THREAD_COUNT; i++ ) {
				int threadNumber = i;
				Thread t = new Thread( () => Runner( provider, go, threadNumber ) );
				threads.Add( t );

				t.Start();
			}

			// block waiting for all threads to reach their blocking point
			Thread.Sleep( TimeSpan.FromMilliseconds( 50 ) );
			Console.WriteLine( "Starting work in " + MethodBase.GetCurrentMethod().Name + " at " + DateTime.UtcNow + " UTC" );
			go.Set();

			foreach( Thread t in threads ) {
				t.Join();
			}

			Console.WriteLine( "Done in " + MethodBase.GetCurrentMethod().Name + " at " + DateTime.UtcNow + " UTC" );
		}

		private static void Runner( 
			IPrivateKeyProvider provider, 
			ManualResetEventSlim go,
			int threadNumber
		) {
			// wait for start signal
			go.Wait();

			for( int i = 0; i < SIGNATURES_PER_THREAD; i++ ) {
				using( D2LSecurityToken securityToken = provider.GetSigningCredentialsAsync()
					.SafeAsync()
					.GetAwaiter()
					.GetResult()
				) {
					string signedToken = Sign( securityToken );
					Thread.Sleep( TimeSpan.FromMilliseconds( 20 ) );
					AssertSignatureVerifiable( securityToken, signedToken );
				}
			}
		}
		
		private static string Sign( D2LSecurityToken securityToken ) {
			JwtSecurityToken jwt = new JwtSecurityToken(
					issuer: TEST_ISSUER,
					signingCredentials: securityToken.GetSigningCredentials()
					);

			JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
			string signedToken = jwtHandler.WriteToken( jwt );

			return signedToken;
		}

		private static void AssertSignatureVerifiable( 
			D2LSecurityToken securityToken, 
			string signedToken 
		) {
			JwtSecurityTokenHandler validationTokenHandler = new JwtSecurityTokenHandler();
			TokenValidationParameters validationParameters = new TokenValidationParameters() {
				ValidateAudience = false,
				ValidateIssuer = false,
				ValidateLifetime = false,
				RequireSignedTokens = true,
				IssuerSigningKey = securityToken.SigningKey
			};
			SecurityToken validatedToken;
			validationTokenHandler.ValidateToken(
				signedToken,
				validationParameters,
				out validatedToken
				);

			JwtSecurityToken validatedJwt = validatedToken as JwtSecurityToken;
			Assert.AreEqual( TEST_ISSUER, validatedJwt.Issuer );
		}
	}
}
