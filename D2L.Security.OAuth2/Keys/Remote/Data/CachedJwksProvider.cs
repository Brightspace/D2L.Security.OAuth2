﻿using System;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Caching;

namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal sealed class CachedJwksProvider : IJwksProvider {
		
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
				CacheResponse cacheResponse = await m_cache.GetAsync( key ).SafeAsync();
				if( cacheResponse.Success ) {
					return new JwksResponse(
						fromCache: true,
						jwksJson: cacheResponse.Value );
				}
			}

			JwksResponse response = await m_innerProvider.RequestJwksAsync( jwksEndpoint ).SafeAsync();
			await m_cache.SetAsync(
				key: key,
				value: response.JwksJson,
				expiry: TimeSpan.FromSeconds( Constants.KEY_MAXAGE_SECONDS )
			).SafeAsync();
			
			return response;
		}
		
	}
}
