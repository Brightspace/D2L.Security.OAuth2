using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Validation.AccessTokens {
	
	[TestFixture]
	internal sealed class AccessTokenExtensionsTests {

		private void MockClaim( Mock<IAccessToken> accessTokenMock, string claimName, string claimValue ) {
			Claim claim = new Claim( claimName, claimValue );
			Claim[] claims = new Claim[] { claim };
			accessTokenMock.SetupGet( x => x.Claims ).Returns( claims );
		}

		[Test]
		public void GetXsrfToken_Success() {
			string expected = "somexsrf";
			var accessTokenMock = new Mock<IAccessToken>();
			MockClaim( accessTokenMock, Constants.Claims.XSRF_TOKEN, expected );
			Assert.AreEqual( expected, accessTokenMock.Object.GetXsrfToken() );
		}

		[Test]
		public void GetXsrfToken_None_ReturnsNull() {
			var accessTokenMock = new Mock<IAccessToken>();
			Assert.IsNull( accessTokenMock.Object.GetXsrfToken() );
		}

		[Test]
		public void GetTenantId_Success() {
			string expected = "sometenantid";
			var accessTokenMock = new Mock<IAccessToken>();
			MockClaim( accessTokenMock, Constants.Claims.TENANT_ID, expected );
			Assert.AreEqual( expected, accessTokenMock.Object.GetTenantId() );
		}

		[Test]
		public void GetAccessTokenId_Success() {
			string expected = "sometokenid";
			var accessTokenMock = new Mock<IAccessToken>();
			MockClaim( accessTokenMock, Constants.Claims.TOKEN_ID, expected );
			Assert.AreEqual( expected, accessTokenMock.Object.GetAccessTokenId() );
		}

		[Test]
		public void GetTenantId_None_ReturnsNull() {
			var accessTokenMock = new Mock<IAccessToken>();
			Assert.IsNull( accessTokenMock.Object.GetTenantId() );
		}

		[Test]
		public void GetScopes_One_Success() {
			var expected = new Scope( "some", "random", "scope" );
			var accessTokenMock = new Mock<IAccessToken>();
			MockClaim( accessTokenMock, Constants.Claims.SCOPE, expected.ToString() );
			IEnumerable<Scope> scopes = accessTokenMock.Object.GetScopes();
			Assert.AreEqual( 1, scopes.Count() );
			Assert.AreEqual( expected, scopes.First() );
		}

		[Test]
		public void GetScopes_Many_Success() {
			var scope1 = new Scope( "some", "scope", "1" );
			var scope2 = new Scope( "some", "scope", "2" );
			var accessTokenMock = new Mock<IAccessToken>();
			MockClaim( accessTokenMock, Constants.Claims.SCOPE, scope1 + " " + scope2 );
			IEnumerable<Scope> scopes = accessTokenMock.Object.GetScopes();
			Assert.AreEqual( 2, scopes.Count() );
			Assert.IsTrue( scopes.Contains( scope1 ) );
			Assert.IsTrue( scopes.Contains( scope2 ) );
		}

		[Test]
		public void GetScopes_None_ReturnsEmpty() {
			var accessTokenMock = new Mock<IAccessToken>();
			IEnumerable<Scope> scopes = accessTokenMock.Object.GetScopes();
			Assert.IsFalse( scopes.Any() );
		}

		[Test]
		public void GetUserId_Success() {
			string expected = "userid-1337";
			var accessTokenMock = new Mock<IAccessToken>();
			MockClaim( accessTokenMock, Constants.Claims.USER_ID, expected.ToString() );
			Assert.AreEqual( expected, accessTokenMock.Object.GetUserId() );
		}
		
		[Test]
		public void GetUserId_None_ReturnsNull() {
			var accessTokenMock = new Mock<IAccessToken>();
			Assert.IsNull( accessTokenMock.Object.GetUserId() );
		}
	}
}
