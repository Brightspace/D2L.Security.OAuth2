using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys.Remote.Data;
using D2L.Security.OAuth2.Validation.Exceptions;

using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Keys.Remote {
	internal sealed class PublicKeyProvider : IPublicKeyProvider {

		private readonly IJwksProvider m_jwksProvider;
		
		public PublicKeyProvider( IJwksProvider jwksProvider ) {
			m_jwksProvider = jwksProvider;
		}

		async Task<D2LSecurityToken> IPublicKeyProvider.GetSecurityTokenAsync(
			Uri jwksEndPoint,
			Guid keyId
		) {

			JwksResponse jwksResponse = await m_jwksProvider.RequestJwksAsync( 
				jwksEndPoint,
				skipCache: false
			).SafeAsync();
			
			var jwks = new JsonWebKeySet( jwksResponse.JwksJson );
			Microsoft.IdentityModel.Protocols.JsonWebKey key;

			if( !TryGetJsonWebKey( jwks, keyId, out key ) ) {
				
				// If the key is not found and the jwks came from the cache,
				// maybe our cache is just stale.  Let's try again.
				// TODO ... DOS concerns?  This could force us to lookup the key a lot
				if( jwksResponse.FromCache ) {
					jwksResponse = await m_jwksProvider.RequestJwksAsync( 
						jwksEndPoint,
						skipCache: true
					).SafeAsync();
				}
				
				jwks = new JsonWebKeySet( jwksResponse.JwksJson );

				if( !TryGetJsonWebKey( jwks, keyId, out key ) ) {
					throw new PublicKeyNotFoundException(
						string.Format( "Could not find jwk with id '{0}'", keyId )
					);
				}
			}

			D2LSecurityToken securityToken = JsonWebKeyToSecurityToken( key );
			return securityToken;
		}
		
		private bool TryGetJsonWebKey( JsonWebKeySet keySet, Guid keyId, out Microsoft.IdentityModel.Protocols.JsonWebKey key ) {
			foreach( Microsoft.IdentityModel.Protocols.JsonWebKey currentKey in keySet.Keys ) {
				if( currentKey.Kid == keyId.ToString() ) {
					key = currentKey;
					return true;
				}
			}

			key = null;
			return false;
		}

		private  D2LSecurityToken JsonWebKeyToSecurityToken( Microsoft.IdentityModel.Protocols.JsonWebKey jsonWebKey ) {
			
			if( jsonWebKey.Kty != "RSA" ) {
				throw new InvalidKeyTypeException( 
					string.Format(
						"Expected key type to be RSA but was {0}",
						jsonWebKey.Kty ) );
			}

			Guid id;
			if( !Guid.TryParse( jsonWebKey.Kid, out id ) ) {
				throw new InvalidKeyTypeException(
					string.Format(
						"Expected GUID keyId, but got {0}",
						jsonWebKey.Kid ) );
			}
			
			var e = Base64UrlEncoder.DecodeBytes( jsonWebKey.E );
			var n = Base64UrlEncoder.DecodeBytes( jsonWebKey.N );

			var rsaParams = new RSAParameters() {
				Exponent = e,
				Modulus = n
			};

			var rsa = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
			rsa.ImportParameters( rsaParams );
			var key = new RsaSecurityKey( rsa );

			var token = new D2LSecurityToken(
				id: id,
				validFrom: DateTime.Now,
				validTo: DateTime.Now.AddSeconds( Constants.KEY_MAXAGE_SECONDS ),
				key: key
			);
			
			return token;

		}
	}
}
