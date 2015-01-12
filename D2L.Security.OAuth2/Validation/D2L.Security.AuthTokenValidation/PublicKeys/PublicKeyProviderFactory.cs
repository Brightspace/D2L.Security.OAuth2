using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations;
using D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations.Default;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	internal static class PublicKeyProviderFactory {

		internal static IPublicKeyProvider Create( string authority ) {
			IOpenIdConfigurationFetcher openIdFetcher = new OpenIdConfigurationFetcher( authority );
			IPublicKeyProvider provider = new PublicKeyProvider( openIdFetcher );
			return provider;
		}
	}
}
