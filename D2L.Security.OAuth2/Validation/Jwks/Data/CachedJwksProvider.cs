using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;

namespace D2L.Security.OAuth2.Validation.Jwks.Data {
	internal sealed class CachedJwksProvider : IJwksProvider {

		private static readonly TimeSpan DEFAULT_EXPIRY = TimeSpan.FromDays( 1 );
		
		private readonly ICache m_cache;
		private readonly IJwksProvider m_innerProvider;

		public CachedJwksProvider(
			ICache cache,
			IJwksProvider innerProvider
		) {
			m_cache = cache;
			m_innerProvider = innerProvider;
		}

		async Task<string> IJwksProvider.RequestJwksAsync( Uri jwksEndpoint, bool skipCache ) {
			string jwksJson;
			string key = jwksEndpoint.ToString();

			if( !skipCache ) {
				if( m_cache.TryGet( key, out jwksJson ) ) {
					return jwksJson;
				}
			}

			jwksJson = await m_innerProvider.RequestJwksAsync( jwksEndpoint ).ConfigureAwait( false );
			m_cache.Set( key, jwksJson, DEFAULT_EXPIRY );
			return jwksJson;
		}
		
	}
}
