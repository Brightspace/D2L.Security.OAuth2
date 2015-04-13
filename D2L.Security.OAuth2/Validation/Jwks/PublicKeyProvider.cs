using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using D2L.Security.OAuth2.Validation.Token;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Validation.Jwks {
	internal sealed class PublicKeyProvider : IPublicKeyProvider {

		private readonly IJwksProvider m_jwksProvider;
		
		public PublicKeyProvider( IJwksProvider jwksProvider ) {
			m_jwksProvider = jwksProvider;
		}

		async Task<SecurityToken> IPublicKeyProvider.GetSecurityTokenAsync(
			Uri jwksEndPoint,
			string keyId
		) {

			string jwksJson = await m_jwksProvider.RequestJwksAsync( 
				jwksEndPoint,
				skipCache: false
			).ConfigureAwait( false );
			
			var jwks = new JsonWebKeySet( jwksJson );
			JsonWebKey key;
			if( !TryGetJsonWebKey( jwks, keyId, out key ) ) {
				
				// If the key is not found, maybe our cache is just 
				// stale.  Let's try again.
				// TODO ... DOS concerns?  This could force us to lookup the key a lot
				jwksJson = await m_jwksProvider.RequestJwksAsync( 
					jwksEndPoint,
					skipCache: true
				).ConfigureAwait( false );

				jwks = new JsonWebKeySet( jwksJson );

				if( !TryGetJsonWebKey( jwks, keyId, out key ) ) {
					throw new KeyNotFoundException(
						string.Format( "Could not find jwk with id '{0}'", keyId )
					);
				}
			}

			SecurityToken securityToken = JsonWebKeyToSecurityToken( key );
			return securityToken;
		}
		
		private bool TryGetJsonWebKey( JsonWebKeySet keySet, string keyId, out JsonWebKey key ) {
			foreach( JsonWebKey currentKey in keySet.Keys ) {
				if( currentKey.Kid == keyId ) {
					key = currentKey;
					return true;
				}
			}

			key = null;
			return false;
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

			// TODO dispose.  Or probably use jparker's ID2LSecurityToken
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
