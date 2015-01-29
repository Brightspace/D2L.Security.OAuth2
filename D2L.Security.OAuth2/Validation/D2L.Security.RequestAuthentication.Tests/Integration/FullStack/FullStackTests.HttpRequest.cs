using System;
using System.Linq;
using System.Web;
using D2L.Security.RequestAuthentication.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed partial class FullStackTests {

		private readonly IRequestAuthenticator m_authenticator = RequestAuthenticatorFactory.Create(
			TestUris.TOKEN_VERIFICATION_AUTHORITY_URI
			);

		[Test]
		public void HttpRequest_Cookie_NoXsrf_Failure() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( TestTokens.ValidNoXsrfOneScope.Jwt );

			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationResult.XsrfMismatch, result );
		}
		
		[Test]
		public void HttpRequest_Cookie_WithXsrf_Success() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( TestTokens.ValidWithXsrfOneScope.Jwt )
				.WithXsrfHeader( TestTokens.ValidWithXsrfOneScope.Xt );

			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
			Assert.AreEqual( TestTokens.ValidWithXsrfOneScope.Sub, principal.UserId );
			Assert.AreEqual( TestTokens.ValidWithXsrfOneScope.Tenantid, principal.TenantId );
			Assert.AreEqual( TestTokens.ValidWithXsrfOneScope.Tenanturl, principal.TenantUrl );

			Assert.AreEqual( 1, principal.Scopes.Count() );
			Assert.AreEqual( TestTokens.ValidWithXsrfOneScope.Scope, principal.Scopes.First() );

			DateTime expectedExpiry = new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc )
				.AddSeconds( TestTokens.ValidWithXsrfOneScope.Exp );

			Assert.AreEqual( PrincipalType.User, principal.Type );
			Assert.AreEqual( TestTokens.ValidWithXsrfOneScope.Xt, principal.Xsrf );
			Assert.AreEqual( TestTokens.ValidWithXsrfOneScope.Jwt, principal.AccessToken );
			Assert.AreEqual( expectedExpiry, principal.SecurityExpiry );
		}

		[Test]
		public void HttpRequest_BearerToken_NoXsrf_Success() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithAuthHeader( TestTokens.ValidNoXsrfOneScope.Jwt );

			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
		}

		[Test]
		public void HttpRequest_BearerToken_WithXsrf_Success() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithAuthHeader( TestTokens.ValidWithXsrfOneScope.Jwt );

			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
		}

		[Test]
		public void HttpRequest_BearerToken_InvalidJwt_Failure() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithAuthHeader( "bogusjwt" );

			ID2LPrincipal principal;
			Assertions.Throws( () => m_authenticator.AuthenticateAndExtract( httpRequest, out principal ) );
		}

		[Test]
		public void HttpRequest_Cookie_InvalidJwt_Failure() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( "bogusjwt" );

			ID2LPrincipal principal;
			Assertions.Throws( () => m_authenticator.AuthenticateAndExtract( httpRequest, out principal ) );
		}

		[Test]
		public void HttpRequest_Cookie_NonMatchingXsrf_Failure() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( TestTokens.ValidWithXsrfOneScope.Jwt )
				.WithXsrfHeader( "bogusxsrfheader" );

			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationResult.XsrfMismatch, result );
		}

		[Test]
		public void HttpRequest_Cookie_NonMatchingXsrf_ExplicitlyNotValidatingXsrf_Success() {
			HttpRequest httpRequest = new HttpRequest( null, "http://d2l.com", null )
				.WithCookie( TestTokens.ValidWithXsrfOneScope.Jwt )
				.WithXsrfHeader( "bogusxsrfheader" );

			IRequestAuthenticator m_authenticator = RequestAuthenticatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI,
				Mode.SkipXsrfValidation
				);

			ID2LPrincipal principal;
			AuthenticationResult result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationResult.Success, result );
		}
	}
}
