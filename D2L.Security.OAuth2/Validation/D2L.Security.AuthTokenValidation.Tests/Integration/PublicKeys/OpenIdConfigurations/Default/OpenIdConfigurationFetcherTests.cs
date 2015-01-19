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
				new OpenIdConfigurationFetcher( TestUris.TOKEN_VERIFICATION_AUTHORITY_URI );

			OpenIdConnectConfiguration configuration = fetcher.Fetch();
			Assert.AreEqual( TestUris.ISSUER_URL, configuration.Issuer );
		}

		[Test]
		public void Fetch_InvalidUrl_Throws() {
			Uri badUrl = new Uri( TestUris.TOKEN_VERIFICATION_AUTHORITY_URI, "somedummyurlfragment/" );
			IOpenIdConfigurationFetcher fetcher = new OpenIdConfigurationFetcher( badUrl );

			Assert.Throws<InvalidOperationException>( () => fetcher.Fetch() );
		}
	}
}
