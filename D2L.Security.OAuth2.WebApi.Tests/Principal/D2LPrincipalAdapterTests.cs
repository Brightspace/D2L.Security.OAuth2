using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Scopes;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Principal {

	[TestFixture]
	internal sealed class D2LPrincipalAdapterTests {

		private const PrincipalType PRINCIPAL_TYPE =
			PrincipalType.User;

		private const string USER_ID = "123";

		private readonly Guid TENANT_ID = Guid.NewGuid();
		private readonly IEnumerable<Scope> m_scopes = new[] { 
			new Scope( "group", "resource", "permission" )
		};
		private readonly IEnumerable<Claim> m_claims = new[] { new Claim( "claim1", "claimvalue1" ) };
		private readonly DateTime m_accessTokenExpiry = DateTime.Now;
		
		private Mock<IAccessToken> m_accessTokenMock;

		[TestFixtureSetUp]
		public void TestFixtureSetUp() {
			m_accessTokenMock = new Mock<IAccessToken>();
			m_accessTokenMock.Setup( x => x.Expiry ).Returns( m_accessTokenExpiry );
			m_accessTokenMock.Setup( x => x.Claims ).Returns( m_claims );
		}

		[Test]
		public void SetID2LPrincipalProperties_GoodValues_ValuesMatch() {

			ID2LPrincipal principal =
				new D2LPrincipalAdapter();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.AreEqual( m_accessTokenMock.Object, principal.AccessToken );
			Assert.AreEqual( PRINCIPAL_TYPE, principal.Type );
			Assert.AreEqual( m_scopes, principal.Scopes );
			Assert.AreEqual( m_claims, principal.AccessToken.Claims );
			Assert.AreEqual( m_accessTokenExpiry, principal.AccessToken.Expiry );
			Assert.AreEqual( TENANT_ID, principal.TenantId );
			Assert.AreEqual( USER_ID, principal.UserId );
		}

		[Test]
		public void IPrincipalProperties_AccessThem_NotGoodValues() {

			IPrincipal principal =
				new D2LPrincipalAdapter();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.Null( principal.Identity );
			Assert.Throws<NotImplementedException>( () => { principal.IsInRole( "random_role" ); } );
		}

		[Test]
		public void ID2LPrincipalProperties_PrincipalNotSet_ExceptionWhenAccessingProperty() {

			ID2LPrincipal principal =
				new D2LPrincipalAdapter();
			Assert.Throws<PrincipalNotAssignedException>( () => { var tenant = principal.TenantId; } );
		}

		private D2LPrincipalAdapter CreateMockPrincipal() {
			Mock<ID2LPrincipal> principalMock = new Mock<ID2LPrincipal>();
			principalMock.Setup( x => x.Type ).Returns( PRINCIPAL_TYPE );
			principalMock.Setup( x => x.Scopes ).Returns( m_scopes );
			principalMock.Setup( x => x.TenantId ).Returns( TENANT_ID );
			principalMock.Setup( x => x.UserId ).Returns( USER_ID );

			principalMock.Setup( x => x.AccessToken ).Returns( m_accessTokenMock.Object );

			return new D2LPrincipalAdapter( principalMock.Object );
		}
	}
}
