using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.Utilities;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.AuthTokenValidation.PublicKeys.Default {
	internal sealed class PublicKeyProvider : IPublicKeyProvider {

		private readonly string m_authority;

		public string _issuer;
		public SecurityToken _token;

		internal PublicKeyProvider( string authority ) {
			m_authority = authority;

			string _authority = FormatAuthority( authority );

			using( HttpMessageHandler _backchannelHttpHandler = new WebRequestHandler() ) {
				using( HttpClient _httpClient = new HttpClient( _backchannelHttpHandler ) ) {
					RetrieveCertificate( new ConfigurationManager<OpenIdConnectConfiguration>( _authority, _httpClient ) );
				}
			}
		}

		Task<IPublicKey> IPublicKeyProvider.Fetch() {
			throw new NotImplementedException();
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

		private X509SecurityToken JsonWebKeyToToken( JsonWebKey jsonWebKey ) {

			IList<string> x5cEntries = jsonWebKey.X5c;
			if( x5cEntries.Count != 1 ) {
				throw new Exception( string.Format( "Expected one x5c entry and found {0}", x5cEntries.Count ) );
			}

			byte[] payload = Convert.FromBase64String( x5cEntries.First() );
			X509Certificate2 certificate = new X509Certificate2( payload );
			X509SecurityToken token = new X509SecurityToken( certificate );
			return token;
		}

		private void RetrieveCertificate( ConfigurationManager<OpenIdConnectConfiguration> _configurationManager ) {
			OpenIdConnectConfiguration result = 
				AsyncHelper.RunSync<OpenIdConnectConfiguration>( async () => await _configurationManager.GetConfigurationAsync() );

			int jsonWebKeyCount = result.JsonWebKeySet.Keys.Count;
			if( jsonWebKeyCount != 1 ) {
				throw new Exception( string.Format( "Expected one json web key and found {0}", jsonWebKeyCount ) );
			}

			_issuer = result.Issuer;
			_token = JsonWebKeyToToken( result.JsonWebKeySet.Keys.First() );
		}
	}
}
