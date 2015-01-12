using System.Net.Http;
using D2L.Security.AuthTokenValidation.Utilities;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.AuthTokenValidation.PublicKeys.OpenIdConfigurations.Default {
	internal sealed class OpenIdConfigurationFetcher : IOpenIdConfigurationFetcher {

		private readonly string m_authority;

		internal OpenIdConfigurationFetcher( string authority ) {
			m_authority = FormatAuthority( authority );
		}

		OpenIdConnectConfiguration IOpenIdConfigurationFetcher.Fetch() {
			OpenIdConnectConfiguration result = null;

			using( HttpMessageHandler httpMessageHandler = new WebRequestHandler() ) {
				using( HttpClient httpClient = new HttpClient( httpMessageHandler ) ) {
					ConfigurationManager<OpenIdConnectConfiguration> configManager =
						new ConfigurationManager<OpenIdConnectConfiguration>( m_authority, httpClient );
					
					result = AsyncHelper.RunSync<OpenIdConnectConfiguration>( 
						async () => await configManager.GetConfigurationAsync() 
						);
				}
			}

			return result;
		}

		private string FormatAuthority( string authority ) {
			if( !authority.EndsWith( "/" ) ) {
				authority += "/";
			}
			authority += ".well-known/openid-configuration";
			return authority;
		}
	}
}
