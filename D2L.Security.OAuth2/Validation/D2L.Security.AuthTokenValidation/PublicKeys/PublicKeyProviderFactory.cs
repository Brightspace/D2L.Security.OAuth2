using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations;
using D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations.Default;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	internal static class PublicKeyProviderFactory {

		private static object Lock = new object();
		private static IPublicKeyProvider Instance;

		internal static IPublicKeyProvider Create( string authority ) {
			if( Instance == null ) {
				lock( Lock ) {
					if( Instance == null ) {
						IOpenIdConfigurationFetcher openIdFetcher = new OpenIdConfigurationFetcher( authority );
						Instance = new PublicKeyProvider( openIdFetcher );
					}
				}
			}
			return Instance;
		}
	}
}
