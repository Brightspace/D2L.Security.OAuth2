using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using D2L.Security.OAuth2.Validation.Token;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Validation.Jwks {
	internal sealed class SecurityTokenProvider : ISecurityTokenProvider {

		private readonly IJwksProvider m_jwksProvider;
		
		public SecurityTokenProvider( IJwksProvider jwksProvider ) {
			m_jwksProvider = jwksProvider;
		}

		async Task<SecurityToken> ISecurityTokenProvider.GetSecurityTokenAsync(
			Uri jwksEndPoint,
			string keyId
		) {

			string jwksJson = await m_jwksProvider.RequestJwksAsync( jwksEndPoint ).ConfigureAwait( false );
			
			var jwks = new JsonWebKeySet( jwksJson );
			
			foreach( JsonWebKey key in jwks.Keys ) {
				if( key.Kid == keyId ) {
					SecurityToken securityToken = JsonWebKeyToSecurityToken( key );
					return securityToken;
				}
			}
			
			throw new Exception( string.Format( "Could not find keyId {0}", keyId ) );
		}

		private SecurityToken JsonWebKeyToSecurityToken( JsonWebKey jsonWebKey ) {
			
			if( jsonWebKey.Kty != TokenValidationConstants.ALLOWED_KEY_TYPE ) {
				throw new Exception( 
					string.Format(
						"Expected key type to be {0} but was {1}",
						TokenValidationConstants.ALLOWED_KEY_TYPE,
						jsonWebKey.Kty
					) 
				);
			}
			
			var e = Base64UrlEncoder.DecodeBytes( jsonWebKey.E );
			var n = Base64UrlEncoder.DecodeBytes( jsonWebKey.N );

			var rsaParams = new RSAParameters() {
				Exponent = e,
				Modulus = n
			};

			// TODO dispose?
			var rsa = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
			rsa.ImportParameters( rsaParams );
			var key = new RsaSecurityKey( rsa );
			
			var token = new NamedKeySecurityToken(
				name: JsonWebKeyParameterNames.Kid,
				id: jsonWebKey.Kid,
				key: key
			);

			return token;

		}
	}
}
