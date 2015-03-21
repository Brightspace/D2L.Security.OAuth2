using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Validation.Token.PublicKeys.OpenIdConfigurations {
	interface IOpenIdConfigurationFetcher {
		OpenIdConnectConfiguration Fetch();
	}
}
