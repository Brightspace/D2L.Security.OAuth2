using System;
using System.Net.Http;
using D2L.Security.OAuth2.Validation.Token.Utilities;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Validation.Token.PublicKeys.OpenIdConfigurations.Default {
	internal sealed class OpenIdConfigurationFetcher : IOpenIdConfigurationFetcher {

		private readonly Uri m_authority;

		internal OpenIdConfigurationFetcher( Uri authority ) {
			m_authority = new Uri( authority, ".well-known/openid-configuration" );
		}

		OpenIdConnectConfiguration IOpenIdConfigurationFetcher.Fetch() {
			OpenIdConnectConfiguration result;

			using( HttpMessageHandler httpMessageHandler = new WebRequestHandler() ) {
				using( HttpClient httpClient = new HttpClient( httpMessageHandler ) ) {
					ConfigurationManager<OpenIdConnectConfiguration> configManager =
						new ConfigurationManager<OpenIdConnectConfiguration>( m_authority.ToString(), httpClient );
					
					result = AsyncHelper.RunSync( 
						async () => await configManager.GetConfigurationAsync() 
						);
				}
			}

			return result;
		}
	}
}
