using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Remote.Data;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys.Remote {
	internal sealed class PublicKeyProvider : IPublicKeyProvider {

		private readonly IJwksProvider m_jwksProvider;
		
		public PublicKeyProvider( IJwksProvider jwksProvider ) {
			m_jwksProvider = jwksProvider;
		}

		async Task<D2LSecurityToken> IPublicKeyProvider.GetSecurityTokenAsync(
			Uri authServiceEndpoint,
			Guid keyId
		) {

			JwksResponse jwksResponse = await m_jwksProvider.RequestJwksAsync( 
				authServiceEndpoint,
				skipCache: false
			).SafeAsync();
			
			var jwks = new JsonWebKeySet( jwksResponse.JwksJson );
			JsonWebKey key;

			if( !jwks.TryGetKey( keyId, out key ) ) {
				
				// If the key is not found and the jwks came from the cache,
				// maybe our cache is just stale.  Let's try again.
				// TODO ... DOS concerns?  This could force us to lookup the key a lot
				if( jwksResponse.FromCache ) {
					jwksResponse = await m_jwksProvider.RequestJwksAsync( 
						authServiceEndpoint,
						skipCache: true
					).SafeAsync();
				}
				
				jwks = new JsonWebKeySet( jwksResponse.JwksJson );
				
				if( !jwks.TryGetKey( keyId, out key ) ) {
					throw new PublicKeyNotFoundException(
						string.Format( "Could not find jwk with id '{0}'", keyId )
					);
				}
			}

			D2LSecurityToken securityToken = key.ToSecurityToken();
			return securityToken;
		}
	}
}
