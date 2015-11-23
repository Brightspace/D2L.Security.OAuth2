using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Services;
using Moq;
using NUnit.Framework;
using SimpleLogInterface;

namespace D2L.Security.OAuth2.Authentication {
	[TestFixture]
	internal sealed class OAuth2AuthenticationFilterTests {
		private Mock<IRequestAuthenticator> m_requestAuthenticator;
		private Mock<ILog> m_log;
		private IAuthenticationFilter m_authenticationFilter;
		private ID2LPrincipal m_principalAfterCallback;
		private HttpAuthenticationContext m_authenticationContext;

		[SetUp]
		public void SetUp() {
			m_requestAuthenticator = new Mock<IRequestAuthenticator>( MockBehavior.Strict );

			m_log = new Mock<ILog>( MockBehavior.Loose );
			var logProvider = new Mock<ILogProvider>( MockBehavior.Strict );
			logProvider
				.Setup( lp => lp.Get( typeof( OAuth2AuthenticationFilter ).FullName ) )
				.Returns( m_log.Object );

			m_principalAfterCallback = null;

			m_authenticationFilter = new OAuth2AuthenticationFilter(
				logProvider.Object,
				m_requestAuthenticator.Object,
				p => m_principalAfterCallback = p
			);

			var request = new HttpRequestMessage();
			var controllerContext = new HttpControllerContext();
			controllerContext.Request = request;
			var actionContext = new HttpActionContext();
			actionContext.ControllerContext = controllerContext;
			m_authenticationContext = new HttpAuthenticationContext( actionContext, null );
		}

		[Test]
		public async Task AuthenticateAsync_ValidationException_401() {
			m_requestAuthenticator
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>(), It.IsAny<AuthenticationMode>() ) )
				.Throws( new ExpiredTokenException( "bleh" ) );

			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();

			Assert.IsNull( m_authenticationContext.Principal );
			Assert.IsNull( m_principalAfterCallback );
			Assert.IsInstanceOfType( typeof( AuthenticationFailureResult ), m_authenticationContext.ErrorResult );
		}

		[Test]
		[ExpectedException(typeof(InvalidCastException))]
		public async Task AuthenticateAsync_OtherException_Throws() {
			m_requestAuthenticator
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>(), It.IsAny<AuthenticationMode>() ) )
				.Throws<InvalidCastException>();
			
			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();
		}

		[Test]
		public async Task AuthenticateAsync_Success() {
			var principalMock = new Mock<ID2LPrincipal>( MockBehavior.Strict );
			principalMock.Setup( p => p.TenantId ).Returns( new Guid() );
			var principal = principalMock.Object;

			m_requestAuthenticator
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>(), It.IsAny<AuthenticationMode>() ) )
				.ReturnsAsync( principal );
			
			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();

			Assert.AreSame( principal, m_principalAfterCallback );
			Assert.IsNotNull( m_authenticationContext.Principal );

			var principalFromContext = m_authenticationContext.Principal as ID2LPrincipal;

			Assert.IsNotNull( principalFromContext );
			Assert.AreEqual( principal.TenantId, principalFromContext.TenantId );
		}

		[Test]
		public async Task ChallengeAsync_DoesntCrash() {
			await m_authenticationFilter
				.ChallengeAsync( null, new CancellationToken() )
				.SafeAsync();
		}
	}
}
