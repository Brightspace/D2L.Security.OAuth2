using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using D2L.Security.AuthTokenValidation.Utilities;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.AuthTokenValidation.PublicKeys.Implementations {
	class DefaultPublicKeyProvider {

		// DISPOSE
		private readonly HttpClient _httpClient;
		private readonly HttpMessageHandler _backchannelHttpHandler;

		private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

		public string _issuer;
		public SecurityToken _token;
		public string _authority;

		public DefaultPublicKeyProvider( string authority ) {

			_authority = FormatAuthority( authority );

			_backchannelHttpHandler = new WebRequestHandler();
			_httpClient = new HttpClient( _backchannelHttpHandler );

			_configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>( _authority, _httpClient );
			RetrieveMetadata();
		}

		public void Decode( string jwt ) {
			JwtSecurityTokenHandler tokenDecoder = new JwtSecurityTokenHandler();
			System.IdentityModel.Tokens.SecurityToken securityToken = tokenDecoder.ReadToken( jwt );

			// should assert tokenDecoder.CanValidate is true
			//IEnumerable<ClaimsIdentity> claims = tokenDecoder.ValidateToken( securityToken ); // should just have one

			TokenValidationParameters validationParameters = new TokenValidationParameters();
			X509CertificateValidator x509CertificateValidator = X509CertificateValidator.None;
			validationParameters.CertificateValidator = x509CertificateValidator;

			ClaimsPrincipal claimsPrincipal = tokenDecoder.ValidateToken( jwt, validationParameters, out securityToken );
		}

		public void Decode2( string jwt ) {

			JwtSecurityTokenHandler tokenDecoder = new JwtSecurityTokenHandler();
			JwtSecurityToken securityToken = (JwtSecurityToken)tokenDecoder.ReadToken( jwt );
			
			var handler = new JwtSecurityTokenHandler {
				Configuration =
					new SecurityTokenHandlerConfiguration {
						CertificateValidationMode = X509CertificateValidationMode.None,
						CertificateValidator = X509CertificateValidator.None
					}
			};

			var parameters = new TokenValidationParameters {
				ValidIssuer = _issuer,
				//IssuerSigningKey = _token.SecurityKeys.First(),
				IssuerSigningKey = new InMemorySymmetricSecurityKey( new byte[] { 1, 3, 3, 7 } ),
				ValidateLifetime = false,
				ValidateAudience = false
			};

			SecurityToken jwtToken;
			ClaimsPrincipal claimsPrincipal = handler.ValidateToken( jwt, parameters, out jwtToken );
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

		private void RetrieveMetadata() {
			var result = AsyncHelper.RunSync<OpenIdConnectConfiguration>( async () => await _configurationManager.GetConfigurationAsync() );
			
			//X509SecurityKey
			int jsonWebKeyCount = result.JsonWebKeySet.Keys.Count;
			if( jsonWebKeyCount != 1 ) {
				throw new Exception( string.Format( "Expected one json web key and found {0}", jsonWebKeyCount ) );
			}

			_issuer = result.Issuer;
			_token = JsonWebKeyToToken( result.JsonWebKeySet.Keys.First() );
		}
	}
}
