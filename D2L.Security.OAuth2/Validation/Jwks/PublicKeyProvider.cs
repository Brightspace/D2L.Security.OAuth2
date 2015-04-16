using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Validation.Jwks {
	internal sealed class PublicKeyProvider : IPublicKeyProvider {

		internal const string ALLOWED_KEY_TYPE = "RSA";

		private readonly IJwksProvider m_jwksProvider;
		
		public PublicKeyProvider( IJwksProvider jwksProvider ) {
			m_jwksProvider = jwksProvider;
		}

		async Task<D2LSecurityToken> IPublicKeyProvider.GetSecurityTokenAsync(
			Uri jwksEndPoint,
			string keyId
		) {

			JwksResponse jwksResponse = await m_jwksProvider.RequestJwksAsync( 
				jwksEndPoint,
				skipCache: false
			).SafeAsync();
			
			var jwks = new JsonWebKeySet( jwksResponse.JwksJson );
			JsonWebKey key;

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

		private  D2LSecurityToken JsonWebKeyToSecurityToken( JsonWebKey jsonWebKey ) {
			
			if( jsonWebKey.Kty != ALLOWED_KEY_TYPE ) {
				throw new InvalidKeyTypeException( 
					string.Format(
						"Expected key type to be {0} but was {1}",
						ALLOWED_KEY_TYPE,
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

			var rsa = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
			rsa.ImportParameters( rsaParams );
			var key = new RsaSecurityKey( rsa );

			var token = new D2LSecurityToken(
				id: jsonWebKey.Kid,
				validFrom: DateTime.Now,
				validTo: DateTime.Now.AddSeconds( Constants.KEY_MAXAGE_SECONDS ),
				key: key
			);
			
			return token;

		}
	}
}
