using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
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
		private HttpAuthenticationContext m_authenticationContext;
		private Mock<ID2LPrincipalDependencyRegistry> m_principalRegistry;

		[SetUp]
		public void SetUp() {
			m_principalRegistry = new Mock<ID2LPrincipalDependencyRegistry>( MockBehavior.Strict );

			m_requestAuthenticator = new Mock<IRequestAuthenticator>( MockBehavior.Strict );

			m_log = new Mock<ILog>( MockBehavior.Loose );
			var logProvider = new Mock<ILogProvider>( MockBehavior.Strict );
			logProvider
				.Setup( lp => lp.Get( typeof( OAuth2AuthenticationFilter ).FullName ) )
				.Returns( m_log.Object );

			m_authenticationFilter = new OAuth2AuthenticationFilter(
				logProvider.Object,
				m_requestAuthenticator.Object,
				m_principalRegistry.Object
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
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>() ) )
				.Throws( new ExpiredTokenException( "bleh" ) );

			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();

			Assert.IsNull( m_authenticationContext.Principal );
			Assert.AreEqual( typeof( AuthenticationFailureResult ), m_authenticationContext.ErrorResult.GetType() );
		}

		[Test]
		[ExpectedException(typeof(InvalidCastException))]
		public async Task AuthenticateAsync_OtherException_Throws() {
			m_requestAuthenticator
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>() ) )
				.Throws<InvalidCastException>();
			
			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();
		}

		[Test]
		public async Task AuthenticateAsync_AnonymousPrincipal_StillSucceeds() {
			// It's up to the authorization attributes to restrict routes to users or services etc.
			var principalMock = new Mock<ID2LPrincipal>( MockBehavior.Strict );
			principalMock.Setup( p => p.Type ).Returns( PrincipalType.Anonymous );
			var principal = principalMock.Object;

			m_requestAuthenticator
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>() ) )
				.ReturnsAsync( principal );

			m_principalRegistry
				.Setup( pr => pr.Register( m_authenticationContext, principalMock.Object ) );
			
			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();

			Assert.IsNotNull( m_authenticationContext.Principal );

			var principalFromContext = m_authenticationContext.Principal as ID2LPrincipal;

			Assert.IsNotNull( principalFromContext );
			Assert.AreEqual( PrincipalType.Anonymous, principalFromContext.Type );

			m_principalRegistry
				.Verify( pr => pr.Register( m_authenticationContext, principalMock.Object ), Times.Once );
		}

		[Test]
		public async Task AuthenticateAsync_Success() {
			var principalMock = new Mock<ID2LPrincipal>( MockBehavior.Strict );
			principalMock.Setup( p => p.Type ).Returns( PrincipalType.User );
			principalMock.Setup( p => p.TenantId ).Returns( new Guid() );
			var principal = principalMock.Object;

			m_requestAuthenticator
				.Setup( ra => ra.AuthenticateAsync( It.IsAny<HttpRequestMessage>() ) )
				.ReturnsAsync( principal );
			
			m_principalRegistry
				.Setup( pr => pr.Register( m_authenticationContext, principalMock.Object ) );
			
			await m_authenticationFilter
				.AuthenticateAsync( m_authenticationContext, new CancellationToken() )
				.SafeAsync();

			Assert.IsNotNull( m_authenticationContext.Principal );

			var principalFromContext = m_authenticationContext.Principal as ID2LPrincipal;

			Assert.IsNotNull( principalFromContext );
			Assert.AreEqual( principal.TenantId, principalFromContext.TenantId );

			m_principalRegistry
				.Verify( pr => pr.Register( m_authenticationContext, principalMock.Object ), Times.Once );
		}

		[Test]
		public async Task ChallengeAsync_DoesntCrash() {
			await m_authenticationFilter
				.ChallengeAsync( null, new CancellationToken() )
				.SafeAsync();
		}
	}
}
