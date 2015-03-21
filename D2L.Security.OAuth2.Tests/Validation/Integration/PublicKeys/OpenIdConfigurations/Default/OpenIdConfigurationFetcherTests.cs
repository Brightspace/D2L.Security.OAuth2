using System;
using D2L.Security.OAuth2.Validation.Token.PublicKeys.OpenIdConfigurations;
using D2L.Security.OAuth2.Validation.Token.PublicKeys.OpenIdConfigurations.Default;
using D2L.Security.OAuth2.Validation.Token.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Token.Tests.Integration.PublicKeys.OpenIdConfigurations.Default {
	
	[TestFixture]
	internal sealed class OpenIdConfigurationFetcherTests {

		[Test]
		public void Fetch_Success() {
			IOpenIdConfigurationFetcher fetcher = 
				new OpenIdConfigurationFetcher( TestUris.TOKEN_VERIFICATION_AUTHORITY_URI );

			Assert.IsNotNull( fetcher.Fetch() );
		}

		[Test]
		public void Fetch_InvalidUrl_Throws() {
			Uri badUrl = new Uri( TestUris.TOKEN_VERIFICATION_AUTHORITY_URI, "somedummyurlfragment/" );
			IOpenIdConfigurationFetcher fetcher = new OpenIdConfigurationFetcher( badUrl );

			Assert.Throws<InvalidOperationException>( () => fetcher.Fetch() );
		}
	}
}
