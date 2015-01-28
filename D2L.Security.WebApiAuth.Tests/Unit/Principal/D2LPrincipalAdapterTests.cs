using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using D2L.Security.RequestAuthentication;
using D2L.Security.WebApiAuth.Principal;
using Moq;
using NUnit.Framework;

namespace D2L.Security.WebApiAuth.Tests.Unit.Principal {

	[TestFixture]
	[Category( "Unit" )]
	internal sealed class D2LPrincipalAdapterTests {

		private const string ACCESS_TOKEN = "access_token";
		private const PrincipalType PRINCIPAL_TYPE = PrincipalType.User;
		private const string TENANT_ID = "tenant_id";
		private const string TENANT_URL = "tenant_url";
		private const long USER_ID = 123;
		private const string XSRF = "xsrf";

		private readonly IEnumerable<string> m_scopes = new[] { "scope1", "scope2" };
		private readonly DateTime m_securityExpiry = DateTime.Now;

		[Test]
		public void SetID2LPrincipalProperties_GoodValues_ValuesMatch() {

			ID2LPrincipal principal = new D2LPrincipalAdapter();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.AreEqual( ACCESS_TOKEN, principal.AccessToken );
			Assert.AreEqual( PRINCIPAL_TYPE, principal.Type );
			Assert.AreEqual( m_scopes, principal.Scopes );
			Assert.AreEqual( m_securityExpiry, principal.SecurityExpiry );
			Assert.AreEqual( TENANT_ID, principal.TenantId );
			Assert.AreEqual( TENANT_URL, principal.TenantUrl );
			Assert.AreEqual( USER_ID, principal.UserId );
			Assert.AreEqual( XSRF, principal.Xsrf );
		}

		[Test]
		public void IPrincipalProperties_AccessThem_NotGoodValues() {
			
			IPrincipal principal = new D2LPrincipalAdapter();

			Thread.CurrentPrincipal = CreateMockPrincipal();

			Assert.Null( principal.Identity );
			Assert.Throws<NotImplementedException>( () => { principal.IsInRole( "random_role" ); } );
		}

		[Test]
		public void ID2LPrincipalProperties_PrincipalNotSet_ExceptionWhenAccessingProperty() {

			ID2LPrincipal principal = new D2LPrincipalAdapter();

			Assert.Throws<PrincipalNotAssignedException>( () => { var tenant = principal.TenantId; } );
		}

		private ID2LPrincipalAdapter CreateMockPrincipal() {

			Mock<ID2LPrincipalAdapter> principalMock = new Mock<ID2LPrincipalAdapter>();
			principalMock.Setup( x => x.AccessToken ).Returns( ACCESS_TOKEN );
			principalMock.Setup( x => x.SecurityExpiry ).Returns( m_securityExpiry );
			principalMock.Setup( x => x.Type ).Returns( PRINCIPAL_TYPE );
			principalMock.Setup( x => x.Scopes ).Returns( m_scopes );
			principalMock.Setup( x => x.TenantId ).Returns( TENANT_ID );
			principalMock.Setup( x => x.TenantUrl ).Returns( TENANT_URL );
			principalMock.Setup( x => x.UserId ).Returns( USER_ID );
			principalMock.Setup( x => x.Xsrf ).Returns( XSRF );

			return principalMock.Object;
		}
	}
}
