using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using D2L.Security.AuthTokenValidation.Utilities;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.AuthTokenValidation.PublicKeys.Default {
	internal sealed class PublicKeyProvider : IPublicKeyProvider {

		private readonly IPublicKey m_key;

		internal PublicKeyProvider( string authority ) {
			authority = FormatAuthority( authority );

			using( HttpMessageHandler httpMessageHandler = new WebRequestHandler() ) {
				using( HttpClient httpClient = new HttpClient( httpMessageHandler ) ) {
					ConfigurationManager<OpenIdConnectConfiguration> configManager =
						new ConfigurationManager<OpenIdConnectConfiguration>( authority, httpClient );
					m_key = RetrieveKey( configManager );
				}
			}
		}

		IPublicKey IPublicKeyProvider.Create() {
			return m_key;
		}

		void IDisposable.Dispose() {
			throw new NotImplementedException();
		}

		private string FormatAuthority( string authority ) {
			if( !authority.EndsWith( "/" ) ) {
				authority += "/";
			}
			authority += ".well-known/openid-configuration";
			return authority;
		}

		private X509SecurityToken JsonWebKeyToSecurityToken( JsonWebKey jsonWebKey ) {

			IList<string> x5cEntries = jsonWebKey.X5c;
			if( x5cEntries.Count != 1 ) {
				throw new Exception( string.Format( "Expected one x5c entry and found {0}", x5cEntries.Count ) );
			}

			byte[] payload = Convert.FromBase64String( x5cEntries.First() );
			X509Certificate2 certificate = new X509Certificate2( payload );
			X509SecurityToken token = new X509SecurityToken( certificate );
			return token;
		}

		private IPublicKey RetrieveKey( ConfigurationManager<OpenIdConnectConfiguration> _configurationManager ) {
			OpenIdConnectConfiguration result = 
				AsyncHelper.RunSync<OpenIdConnectConfiguration>( async () => await _configurationManager.GetConfigurationAsync() );

			IList<JsonWebKey> jsonWebKeys = result.JsonWebKeySet.Keys;
			if( jsonWebKeys.Count != 1 ) {
				throw new Exception( string.Format( "Expected one json web key and found {0}", jsonWebKeys.Count ) );
			}

			SecurityToken securityToken = JsonWebKeyToSecurityToken( jsonWebKeys[0] );
			string issuer = result.Issuer;

			return new PublicKey( securityToken, issuer );
		}
	}
}
