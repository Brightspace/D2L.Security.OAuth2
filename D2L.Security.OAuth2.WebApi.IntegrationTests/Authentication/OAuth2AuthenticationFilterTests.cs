using System.Threading.Tasks;
using NUnit.Framework;
using D2L.Services;
using System.Net;
using System.Net.Http;
using System;
using System.Net.Http.Headers;

namespace D2L.Security.OAuth2.Authentication {
	[TestFixture]
	internal sealed class OAuth2AuthenticationFilterTests {
		[Test]
		public async Task Basic_NoAuth_401() {
			await RunTest( "/authentication/basic", HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_GarbageJwt_401() {
			const string GARBAGE_JWT = "foo";

			await RunTest( "/authentication/basic", GARBAGE_JWT, HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_ExpiredJwt_401() {
			string dayOldJwt = await SetUpFixture
				.GetAccessTokenValidForAMinute(
					issuedAtTime: DateTime.UtcNow - TimeSpan.FromDays( 1 )
				).SafeAsync();

			await RunTest( "/authentication/basic", dayOldJwt, HttpStatusCode.Unauthorized )
				.SafeAsync();
		}

		[Test]
		public async Task Basic_ValidJwt_204() {
			string validJwt = await SetUpFixture
				.GetAccessTokenValidForAMinute()
				.SafeAsync();

			await RunTest( "/authentication/basic", validJwt, HttpStatusCode.NoContent )
				.SafeAsync();
		}

		[Test]
		public async Task Anonymous_NoAuth_204() {
			await RunTest( "/authentication/anonymous", HttpStatusCode.NoContent )
				.SafeAsync();
		}

		private Task RunTest( string route, HttpStatusCode expectedStatusCode ) {
			return RunTest( route, null, expectedStatusCode ); 
		}

		private async Task RunTest( string route, string jwt, HttpStatusCode expectedStatusCode ) {
			using( var client = SetUpFixture.GetHttpClient() ) {

				var req = new HttpRequestMessage();
				req.Method = HttpMethod.Get;
				req.RequestUri = new Uri( client.BaseAddress, route );

				if( jwt != null ) {
					req.Headers.Authorization = new AuthenticationHeaderValue( "Bearer", jwt );
				}

				using ( var resp = await client.SendAsync( req ).SafeAsync() ) {
					Assert.AreEqual( expectedStatusCode, resp.StatusCode );
				}
			}
		}
	}
}
