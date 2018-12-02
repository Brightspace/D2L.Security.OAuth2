using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Caching {
	internal sealed class NullCache : ICache {

		Task<CacheResponse> ICache.GetAsync( string key ) {

			return Task.FromResult(
				new CacheResponse(
					success: false,
					value: null
				)
			);
		}

		Task ICache.SetAsync(
			string key,
			string value,
			TimeSpan expiry
		) {
			return Task.FromResult( 0 );
		}

		Task ICache.RemoveAsync( string key ) {
			return Task.FromResult( 0 );
		}
	}
}
