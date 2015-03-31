using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using D2L.Security.OAuth2.Validation.Token;
using Microsoft.IdentityModel.Protocols;

namespace D2L.Security.OAuth2.Validation.Jwks {
	internal sealed class SecurityKeyProvider {

		private readonly IJwksProvider m_jwksProvider;
		
		public SecurityKeyProvider( IJwksProvider jwksProvider ) {
			m_jwksProvider = jwksProvider;
		}

		public async Task<SecurityKey> GetSecurityKeyAsync( Uri jwksEndPoint, string keyId ) {

			string jwksJson = await m_jwksProvider.RequestJwksAsync( jwksEndPoint );
			
			var jwks = new JsonWebKeySet( jwksJson );
			
			foreach( JsonWebKey key in jwks.Keys ) {
				if( key.Kid == keyId ) {
					SecurityKey securityKey = JsonWebKeyToSecurityKey( key );
					return securityKey;
				}
			}
			
			throw new Exception( string.Format( "Could not find keyId {0}", keyId ) );
		}

		private SecurityKey JsonWebKeyToSecurityKey( JsonWebKey jsonWebKey ) {
			
			if( jsonWebKey.Kty != TokenValidationConstants.ALLOWED_KEY_TYPE ) {
				throw new Exception( 
					string.Format( "Expected key type to be {0} but was {1}", TokenValidationConstants.ALLOWED_KEY_TYPE, jsonWebKey.Kty ) 
				);
			}

			IList<string> x5cEntries = jsonWebKey.X5c;
			if( x5cEntries.Count != 1 ) {
				throw new Exception( string.Format( "Expected one x5c entry but got {0}", x5cEntries.Count ) );
			}

			byte[] payload = Convert.FromBase64String( x5cEntries.First() );
			var certificate = new X509Certificate2( payload );
			var token = new X509SecurityToken( certificate );
			
			if( token.SecurityKeys.Count != 1 ) {
				throw new Exception( string.Format( "Expected one security key but got {0}", token.SecurityKeys.Count ) );
			}

			return token.SecurityKeys[0];
		}
	}
}
