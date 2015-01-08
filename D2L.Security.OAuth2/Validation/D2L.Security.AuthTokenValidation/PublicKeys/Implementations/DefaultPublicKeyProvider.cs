using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using D2L.Security.AuthTokenValidation.Utilities;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.AuthTokenValidation.PublicKeys.Implementations {
	class DefaultPublicKeyProvider {

		// DISPOSE
		private readonly HttpClient _httpClient;
		private readonly HttpMessageHandler _backchannelHttpHandler;

		private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

		public string _issuer;
		public IEnumerable<SecurityToken> _tokens;

		public DefaultPublicKeyProvider( string authority ) {

			authority = FormatAuthority( authority );

			_backchannelHttpHandler = new WebRequestHandler();
			_httpClient = new HttpClient( _backchannelHttpHandler );

			_configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>( authority, _httpClient );
			RetrieveMetadata();
		}
		
		private string FormatAuthority( string authority ) {
			if( !authority.EndsWith( "/" ) ) {
				authority += "/";
			}
			authority += ".well-known/openid-configuration";
			return authority;
		}

		private void RetrieveMetadata() {
			var result = AsyncHelper.RunSync<OpenIdConnectConfiguration>( async () => await _configurationManager.GetConfigurationAsync() );
			var tokens = from key in result.JsonWebKeySet.Keys
						 select new X509SecurityToken( new X509Certificate2( Convert.FromBase64String( key.X5c.First() ) ) );

			_issuer = result.Issuer;
			_tokens = tokens;
		}
	}
}
