using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Caching {
	internal sealed class NullCache : ICache {

		private static readonly CacheResponse NULL_RESPONSE = new CacheResponse( success: false, value: null );

		Task<CacheResponse> ICache.GetAsync( string key ) => Task.FromResult( NULL_RESPONSE );

		Task ICache.SetAsync( string key, string value, TimeSpan expiry ) => Task.CompletedTask;

		Task ICache.RemoveAsync( string key ) => Task.CompletedTask;
	}
}
