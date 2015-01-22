using System.Net;
using System.Security.Authentication;
using System.Threading;
using Moq;
using NUnit.Framework;

namespace D2L.Security.WebApiAuthFilter.Tests {

	[TestFixture]
	[Category( "Unit Test" )]
	internal sealed class AuthorizationFilterTests {

		private const string FAKE_GOOD_JWT = "FAKE_GOOD_JWT_TOKEN";
		private const string FAKE_BAD_JWT = "FAKE_BAD_JWT_TOKEN";
		private const string FAKE_TENANT_ID = "FAKE_TENANT_ID";

		private AuthorizationFilter m_authFilter;

		[TestFixtureSetUp]
		public void TestFixtureSetUp() {

			Mock<IAuthTokenValidatorFactory> authTokenValidatorFactoryMock = new Mock<IAuthTokenValidatorFactory>();
			Mock<IAuthTokenValidator> authTokenValidatorMock = new Mock<IAuthTokenValidator>();
			Mock<IGenericPrincipal> principalMock = new Mock<IGenericPrincipal>();

			principalMock.Setup( x => x.TenantId )
				.Returns( FAKE_TENANT_ID );

			authTokenValidatorMock.Setup( x => x.VerifyAndDecode( FAKE_GOOD_JWT ) )
				.Returns( principalMock.Object );

			// This is here because there's a test below that uses an invalid scheme, which results in a null jwt
			authTokenValidatorMock.Setup( x => x.VerifyAndDecode( (string)null ) )
				.Throws<AuthenticationException>();

			authTokenValidatorMock.Setup( x => x.VerifyAndDecode( FAKE_BAD_JWT ) )
				.Throws<AuthenticationException>();

			authTokenValidatorFactoryMock.Setup( x => x.Create() )
				.Returns( () => authTokenValidatorMock.Object );

			m_authFilter =
				new AuthorizationFilter( authTokenValidatorFactoryMock.Object, NullLogProvider.Instance );
		}

		[Test]
		public void OnAuthorization_OnlyHeader_FetchesSuccessfully() {

			HttpActionContext actionContext = BuildActionContext( true, false );

			m_authFilter.OnAuthorization( actionContext );

			Assert.True( Thread.CurrentPrincipal is IGenericPrincipal );
			IGenericPrincipal principal = (IGenericPrincipal)Thread.CurrentPrincipal;
			Assert.AreEqual( FAKE_TENANT_ID, principal.TenantId );
		}

		[Test]
		public void OnAuthorization_OnlyCookie_FetchesSuccessfully() {

			HttpActionContext actionContext = BuildActionContext( false, true );

			m_authFilter.OnAuthorization( actionContext );

			Assert.True( Thread.CurrentPrincipal is IGenericPrincipal );
			IGenericPrincipal principal = (IGenericPrincipal)Thread.CurrentPrincipal;
			Assert.AreEqual( FAKE_TENANT_ID, principal.TenantId );
		}

		[Test]
		public void OnAuthorization_BothHeaderAndCookie_Unauthorized() {

			HttpActionContext actionContext = BuildActionContext( true, true );

			m_authFilter.OnAuthorization( actionContext );

			Assert.AreEqual( HttpStatusCode.Unauthorized, actionContext.Response.StatusCode );
		}

		[Test]
		public void OnAuthorization_HeaderWithUnexpectedScheme_Unauthorized() {

			HttpActionContext actionContext = BuildActionContext( true, false, "BAD_SCHEME" );

			m_authFilter.OnAuthorization( actionContext );

			Assert.AreEqual( HttpStatusCode.Unauthorized, actionContext.Response.StatusCode );
		}

		[Test]
		public void OnAuthorization_NoAuth_Unauthorized() {

			HttpActionContext actionContext = BuildActionContext( false, false );

			m_authFilter.OnAuthorization( actionContext );

			Assert.AreEqual( HttpStatusCode.Unauthorized, actionContext.Response.StatusCode );
		}

		private HttpActionContext BuildActionContext(
			bool setAuthHeader,
			bool setAuthCookie,
			string scheme = "Bearer"
			) {

			HttpRequestMessage request = new HttpRequestMessage();
			if( setAuthHeader ) {
				request.Headers.Authorization = new AuthenticationHeaderValue( scheme, FAKE_GOOD_JWT );
			}
			if( setAuthCookie ) {
				request.Headers.Add( "Cookie", "d2lApi=" + FAKE_GOOD_JWT );
			}

			return new HttpActionContext(
				new HttpControllerContext( new HttpConfiguration(), new HttpRouteData( new HttpRoute() ), request ),
				new ReflectedHttpActionDescriptor()
				);
		}
	}
}
