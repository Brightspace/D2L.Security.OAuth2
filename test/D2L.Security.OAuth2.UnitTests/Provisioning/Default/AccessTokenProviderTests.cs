﻿using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Scopes;
using D2L.Services;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Provisioning.Default {
	[TestFixture]
	internal sealed class AccessTokenProviderTests {
		private static class TestData {
			public const string ISSUER = "someIssuer";
			public static Guid TENANT_ID = Guid.NewGuid();
			public const string USER = "someUser";
			public const string XSRF_TOKEN = "someXsrfToken";
		}

		private IPublicKeyDataProvider m_publicKeyDataProvider;
		private ITokenSigner m_tokenSigner;
		private IAccessTokenProvider m_accessTokenProvider;
		private JwtSecurityToken m_actualAssertion;

		[SetUp]
		public void SetUp() {
			Mock<IAuthServiceClient> clientMock = new Mock<IAuthServiceClient>();
			clientMock
				.Setup( x => x.ProvisionAccessTokenAsync( It.IsAny<string>(), It.IsAny<IEnumerable<Scope>>() ) )
				.Callback<string, IEnumerable<Scope>>( ( assertion, _ ) => {
					var tokenHandler = new JwtSecurityTokenHandler();
					m_actualAssertion = ( JwtSecurityToken )tokenHandler.ReadToken( assertion );
				} )
				.ReturnsAsync( value: null );

#pragma warning disable 618
			m_publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618

			m_tokenSigner = RsaTokenSignerFactory.Create( m_publicKeyDataProvider );
			m_accessTokenProvider = new AccessTokenProvider( m_tokenSigner, clientMock.Object );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_AssertionTokenIsSigned() {
			var claims = new List<Claim>{
				new Claim( Constants.Claims.ISSUER, TestData.ISSUER ),
				new Claim( Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() ),
				new Claim( Constants.Claims.USER_ID, TestData.USER )
			};

			var scopes = new Scope[] { };

			await m_accessTokenProvider
				.ProvisionAccessTokenAsync( claims, scopes )
				.ConfigureAwait( false );

			var publicKeys = ( await m_publicKeyDataProvider.GetAllAsync().ConfigureAwait( false ) ).ToList();

			string expectedKeyId = publicKeys.First().Id.ToString();
			string actualKeyId = m_actualAssertion.Header.Kid;

			Assert.AreEqual( 1, publicKeys.Count );
			Assert.AreEqual( expectedKeyId, actualKeyId );

			AssertClaimEquals( m_actualAssertion, Constants.Claims.ISSUER, TestData.ISSUER );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.USER_ID, TestData.USER );
		}

		[Test]
		public async Task ProvisionAccessTokenAsync_LegacyClaimSetOverload_DoesRightThing() {
			var claimSet = new[] {
				new Claim( Constants.Claims.ISSUER, TestData.ISSUER ),
				new Claim( Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() ),
				new Claim(Constants.Claims.USER_ID, TestData.USER )
			};

			await m_accessTokenProvider
				.ProvisionAccessTokenAsync( claimSet, new Scope[] { } )
				.ConfigureAwait( false );

			AssertClaimEquals( m_actualAssertion, Constants.Claims.ISSUER, TestData.ISSUER );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.TENANT_ID, TestData.TENANT_ID.ToString() );
			AssertClaimEquals( m_actualAssertion, Constants.Claims.USER_ID, TestData.USER );
		}

		private void AssertClaimEquals( JwtSecurityToken token, string name, string value ) {
			Claim claim = token.Claims.FirstOrDefault( c => c.Type == name );
			Assert.IsNotNull( claim );
			Assert.AreEqual( value, claim.Value );
		}
	}
}
