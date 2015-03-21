using System;
using D2L.Security.OAuth2.Validation.Token.PublicKeys.Default;
using D2L.Security.OAuth2.Validation.Token.PublicKeys.OpenIdConfigurations;
using D2L.Security.OAuth2.Validation.Token.PublicKeys.OpenIdConfigurations.Default;

namespace D2L.Security.OAuth2.Validation.Token.PublicKeys {
	internal static class PublicKeyProviderFactory {

		internal static IPublicKeyProvider Create( Uri authority ) {
			IOpenIdConfigurationFetcher openIdFetcher = new OpenIdConfigurationFetcher( authority );
			IPublicKeyProvider provider = new PublicKeyProvider( openIdFetcher );
			return provider;
		}
	}
}
