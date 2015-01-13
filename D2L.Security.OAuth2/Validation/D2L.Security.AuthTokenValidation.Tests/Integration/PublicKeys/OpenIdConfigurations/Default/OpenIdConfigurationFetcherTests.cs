using System;
using D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations;
using D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations.Default;
using D2L.Security.AuthTokenValidation.Tests.Utilities;
using Microsoft.IdentityModel.Protocols;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.PublicKeys.OpenIdConfigurations.Default {
	
	[TestFixture]
	internal sealed class OpenIdConfigurationFetcherTests {

		[Test]
		public void Fetch_Success() {
			IOpenIdConfigurationFetcher fetcher = 
				new OpenIdConfigurationFetcher( TestUrls.TOKEN_VERIFICATION_AUTHORITY_URL );

			OpenIdConnectConfiguration configuration = fetcher.Fetch();
			Assert.AreEqual( TestUrls.ISSUER_URL, configuration.Issuer );
		}

		[Test]
		public void Fetch_InvalidUrl_Throws() {
			string badUrl = TestUrls.TOKEN_VERIFICATION_AUTHORITY_URL + "somedummyurlfragment/";
			IOpenIdConfigurationFetcher fetcher = new OpenIdConfigurationFetcher( badUrl );

			Assert.Throws<InvalidOperationException>( () => fetcher.Fetch() );
		}
	}
}
