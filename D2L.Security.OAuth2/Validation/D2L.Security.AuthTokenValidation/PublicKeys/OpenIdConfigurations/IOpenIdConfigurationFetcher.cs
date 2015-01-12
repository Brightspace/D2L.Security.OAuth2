using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations {
	interface IOpenIdConfigurationFetcher {
		OpenIdConnectConfiguration Fetch();
	}
}
