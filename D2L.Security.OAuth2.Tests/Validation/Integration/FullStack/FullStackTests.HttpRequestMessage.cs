using System;
using System.Linq;
using System.Net.Http;
using D2L.Security.OAuth2.Validation.Request.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed partial class FullStackTests {
		/*
		[Test]
		public void HttpRequestMessage_Cookie_NoXsrfHeader_Failure() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithCookie( TestTokens.ValidWithXsrfTwoScopesNoUser.Jwt );

			ID2LPrincipal principal;
			AuthenticationStatus result = m_authenticator.AuthenticateAsync( httpRequest, out principal );
			Assert.AreEqual( AuthenticationStatus.XsrfMismatch, result );
		}

		[Test]
		public void HttpRequestMessage_Cookie_WithXsrfHeader_Success() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithCookie( TestTokens.ValidWithXsrfTwoScopesNoUser.Jwt )
				.WithXsrfHeader( TestTokens.ValidWithXsrfTwoScopesNoUser.Xt );

			ID2LPrincipal principal;
			AuthenticationStatus result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );

			Assert.AreEqual( AuthenticationStatus.Success, result );
			Assert.IsNull( principal.UserId );
			Assert.AreEqual( TestTokens.ValidWithXsrfTwoScopesNoUser.Tenantid, principal.TenantId );
			Assert.AreEqual( TestTokens.ValidWithXsrfTwoScopesNoUser.Tenanturl, principal.TenantUrl );

			Assert.AreEqual( 2, principal.Scopes.Count() );
			Assert.IsTrue( principal.Scopes.Contains( TestTokens.ValidWithXsrfTwoScopesNoUser.Scope1 ) );
			Assert.IsTrue( principal.Scopes.Contains( TestTokens.ValidWithXsrfTwoScopesNoUser.Scope2 ) );

			DateTime expectedExpiry = new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc )
				.AddSeconds( TestTokens.ValidWithXsrfTwoScopesNoUser.Exp );

			Assert.AreEqual( PrincipalType.Service, principal.Type );
			Assert.AreEqual( TestTokens.ValidWithXsrfTwoScopesNoUser.Xt, principal.Xsrf );
			Assert.AreEqual( TestTokens.ValidWithXsrfTwoScopesNoUser.Jwt, principal.AccessToken );
			Assert.AreEqual( expectedExpiry, principal.AccessTokenExpiry );
		}

		[Test]
		public void HttpRequestMessage_BearerToken_NoXsrf_Success() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithAuthHeader( TestTokens.ValidNoXsrfOneScope.Jwt );

			ID2LPrincipal principal;
			AuthenticationStatus result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
		}

		[Test]
		public void HttpRequestMessage_BearerToken_WithXsrf_Success() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithAuthHeader( TestTokens.ValidWithXsrfOneScope.Jwt );

			ID2LPrincipal principal;
			AuthenticationStatus result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
		}

		[Test]
		public void HttpRequestMessage_BearerToken_InvalidJwt_Failure() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithAuthHeader( "bogusjwt" );

			ID2LPrincipal principal;
			Assertions.Throws( () => m_authenticator.AuthenticateAndExtract( httpRequest, out principal ) );
		}

		[Test]
		public void HttpRequestMessage_Cookie_InvalidJwt_Failure() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithCookie( "bogusjwt" );

			ID2LPrincipal principal;
			Assertions.Throws( () => m_authenticator.AuthenticateAndExtract( httpRequest, out principal ) );
		}

		[Test]
		public void HttpRequestMessage_Cookie_NonMatchingXsrf_Failure() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithCookie( TestTokens.ValidWithXsrfOneScope.Jwt )
				.WithXsrfHeader( "bogusxsrfheader" );

			ID2LPrincipal principal;
			AuthenticationStatus result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationStatus.XsrfMismatch, result );
		}

		[Test]
		public void HttpRequestMessage_Cookie_NonMatchingXsrf_ExplicitlyNotValidatingXsrf_Success() {
			HttpRequestMessage httpRequest = new HttpRequestMessage()
				.WithCookie( TestTokens.ValidWithXsrfOneScope.Jwt )
				.WithXsrfHeader( "bogusxsrfheader" );

			IRequestAuthenticator m_authenticator = RequestAuthenticatorFactory.Create(
				TestUris.TOKEN_VERIFICATION_AUTHORITY_URI,
				AuthenticationMode.SkipXsrfValidation
				);

			ID2LPrincipal principal;
			AuthenticationStatus result = m_authenticator.AuthenticateAndExtract( httpRequest, out principal );
			Assert.AreEqual( AuthenticationStatus.Success, result );
		}*/
	}
}
