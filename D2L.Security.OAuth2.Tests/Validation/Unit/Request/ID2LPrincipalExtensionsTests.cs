using System.Collections.Generic;
using System.Security.Claims;
using D2L.Security.OAuth2.Validation.Request;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Validation.Unit.Request {
	
	[TestFixture]
	internal sealed class ID2LPrincipalExtensionsTests {

		[Test]
		public void GetAccessTokenId_NullPrincipal_Empty() {
			Assert.AreEqual( "", ID2LPrincipalExtensions.GetAccessTokenId( null ) );
		}

		[Test]
		public void GetAccessTokenId_NullClaims_Empty() {
			Mock<ID2LPrincipal> principalMock = new Mock<ID2LPrincipal>();
			principalMock
				.SetupGet( x => x.AllClaims )
				.Returns( null as IEnumerable<Claim> );

			Assert.AreEqual( "", principalMock.Object.GetAccessTokenId() );
		}

		[Test]
		public void GetAccessTokenId_NoTokenIdClaim_Empty() {
			List<Claim> claims = new List<Claim>();
			claims.Add( new Claim( "someClaimType", "someClaimValue" ) );

			Mock<ID2LPrincipal> principalMock = new Mock<ID2LPrincipal>();
			principalMock
				.SetupGet( x => x.AllClaims )
				.Returns( claims );

			Assert.AreEqual( "", principalMock.Object.GetAccessTokenId() );
		}

		[Test]
		public void GetAccessTokenId_Success() {
			string tokenId = "theTokenId";
			List<Claim> claims = new List<Claim>();
			claims.Add( new Claim( "someClaimType", "someClaimValue" ) );
			claims.Add( new Claim( Constants.Claims.TOKEN_ID, tokenId ) );

			Mock<ID2LPrincipal> principalMock = new Mock<ID2LPrincipal>();
			principalMock
				.SetupGet( x => x.AllClaims )
				.Returns( claims );

			Assert.AreEqual( tokenId, principalMock.Object.GetAccessTokenId() );
		}
	}
}
