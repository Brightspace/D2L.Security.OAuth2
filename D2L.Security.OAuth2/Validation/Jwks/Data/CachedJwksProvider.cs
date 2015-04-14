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

		async Task<JwksResponse> IJwksProvider.RequestJwksAsync( Uri jwksEndpoint, bool skipCache ) {
			string key = jwksEndpoint.ToString();

			if( !skipCache ) {
				string jwksJson;
				if( m_cache.TryGet( key, out jwksJson ) ) {
					return new JwksResponse(
						fromCache: true,
						jwksJson: jwksJson );
				}
			}

			JwksResponse response = await m_innerProvider.RequestJwksAsync( jwksEndpoint ).ConfigureAwait( false );
			m_cache.Set( key, response.JwksJson, DEFAULT_EXPIRY );
			return response;
		}
		
	}
}
