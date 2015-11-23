using System;
using Microsoft.Owin.Hosting;
using NUnit.Framework;
using D2L.Services;
using Owin;
using System.Web.Http;
using D2L.Security.OAuth2.Authentication;
using SimpleLogInterface;
using System.Net.Http;
using D2L.Security.OAuth2.Validation.Request;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Keys;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Collections.Generic;

namespace D2L.Security.OAuth2.Authentication {
	[SetUpFixture]
	public sealed class SetUpFixture {
		const long PORT = 8916; // TODO: do this better
		private IDisposable m_disposeHandle;
		private static ITokenSigner m_signer; // static is ok because only nunit should be instantiating this

		[SetUp]
		public void BeforeAnyTests() {
			var options = new StartOptions();
			options.Urls.Add( "http://+:" + PORT );

			m_disposeHandle = WebApp.Start( options, OwinStartup );

		}

		[TearDown]
		public void AfterAllTests() {
			m_disposeHandle.SafeDispose();
		}

		public static HttpClient GetHttpClient() {
			var client = new HttpClient();
			client.BaseAddress = new Uri( "http://localhost:" + PORT );
			return client;
		}

		public static Task<string> GetAccessTokenValidForAMinute() {
			return GetAccessTokenValidForAMinute( DateTime.UtcNow );	
		}

		public static async Task<string> GetAccessTokenValidForAMinute( DateTime issuedAtTime ) {
			var claims = new List<Claim>();

			// TODO: allow customizing
			claims.Add( new Claim( Constants.Claims.SCOPE, "*:*:*" ) );

			// TODO: allow customizing
			claims.Add( new Claim( Constants.Claims.TENANT_ID, Guid.NewGuid().ToString() ) );

			return await m_signer.SignAsync(
				new UnsignedToken(
					issuer: Constants.ACCESS_TOKEN_ISSUER,
					audience: Constants.ACCESS_TOKEN_AUDIENCE,
					claims: claims,
					notBefore: issuedAtTime,
					expiresAt: issuedAtTime + TimeSpan.FromMinutes( 1 )
				)
			).SafeAsync();
		}

		private IRequestAuthenticator CreateRequestAuthenticator() {
			IPublicKeyDataProvider publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
			m_signer = EcDsaTokenSignerFactory.Create( publicKeyDataProvider, EcDsaTokenSignerFactory.Curve.P256 );

			IAccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory.CreateLocalValidator( publicKeyDataProvider );

			IRequestAuthenticator requestAuthenticator = RequestAuthenticatorFactory.Create( accessTokenValidator );

			return requestAuthenticator;
		}

		private void OwinStartup( IAppBuilder appBuilder ) {
			HttpConfiguration config = new HttpConfiguration();

			var authFilter = new OAuth2AuthenticationFilter(
				logProvider: NullLogProvider.Instance,
				requestAuthenticator: CreateRequestAuthenticator(),
				principalCallback: p => { }
			);

			config.MapHttpAttributeRoutes();
			
			// TODO: adding this globally might suck later depending on what we want to test
			config.Filters.Add( authFilter );

			config.EnsureInitialized();

			appBuilder.UseWebApi( config );
		}
	}
}
