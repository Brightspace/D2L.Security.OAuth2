using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using D2L.Security.RequestAuthentication;
using D2L.Security.WebApiAuth.Principal;
using D2L.Security.WebApiAuth.Principal.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.WebApiAuth.Tests.Unit.Principal.Default {

	[TestFixture]
	[Category( "Unit" )]
	internal sealed class D2LPrincipalAdapterTests {

		private const string CLIENT_ID = "client_id";
		private const bool IS_BROWSER_USER = true;
		private const bool IS_SERVICE = true;
		private const string TENANT_ID = "tenant_id";
		private const string TENANT_URL = "tenant_url";
		private const long USER_ID = 123;

		private readonly IEnumerable<string> m_scopes = new[] { "scope1", "scope2" };

		[Test]
		public void SetID2LPrincipalProperties_GoodValues_ValuesMatch() {

			ID2LPrincipal principal = new D2LPrincipalAdapter();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.AreEqual( CLIENT_ID, principal.ClientId );
			Assert.AreEqual( IS_BROWSER_USER, principal.IsBrowserUser );
			Assert.AreEqual( IS_SERVICE, principal.IsService );
			Assert.AreEqual( m_scopes, principal.Scopes );
			Assert.AreEqual( TENANT_ID, principal.TenantId );
			Assert.AreEqual( TENANT_URL, principal.TenantUrl );
			Assert.AreEqual( USER_ID, principal.UserId );
		}

		[Test]
		public void IPrincipalProperties_AccessThem_NotGoodValues() {
			
			IPrincipal principal = new D2LPrincipalAdapter();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.Null( principal.Identity );
			Assert.Throws<NotImplementedException>( () => { principal.IsInRole( "random_role" ); } );
		}

		[Test]
		public void IsBrowserUser_NotCrossedWithOtherBools() {

			ID2LPrincipal principal = new D2LPrincipalAdapter();
			Thread.CurrentPrincipal = CreateMockPrincipal( true, false );
			Assert.True( principal.IsBrowserUser );
			Assert.False( principal.IsService );
		}

		[Test]
		public void IsService_NotCrossedWithOtherBools() {

			ID2LPrincipal principal = new D2LPrincipalAdapter();
			Thread.CurrentPrincipal = CreateMockPrincipal( false, true );
			Assert.False( principal.IsBrowserUser );
			Assert.True( principal.IsService );
		}

		[Test]
		public void ID2LPrincipalProperties_PrincipalNotSet_ExceptionWhenAccessingProperty() {

			ID2LPrincipal principal = new D2LPrincipalAdapter();

			Assert.Throws<PrincipalNotAssignedException>( () => { var tenant = principal.TenantId; } );
		}

		private ID2LPrincipalAdapter CreateMockPrincipal( bool isBrowserUser = IS_SERVICE, bool isService = IS_BROWSER_USER ) {

			Mock<ID2LPrincipalAdapter> principalMock = new Mock<ID2LPrincipalAdapter>();
			principalMock.Setup( x => x.ClientId ).Returns( CLIENT_ID );
			principalMock.Setup( x => x.IsBrowserUser ).Returns( isBrowserUser );
			principalMock.Setup( x => x.IsService ).Returns( isService );
			principalMock.Setup( x => x.Scopes ).Returns( m_scopes );
			principalMock.Setup( x => x.TenantId ).Returns( TENANT_ID );
			principalMock.Setup( x => x.TenantUrl ).Returns( TENANT_URL );
			principalMock.Setup( x => x.UserId ).Returns( USER_ID );

			return principalMock.Object;
		}
	}
}
