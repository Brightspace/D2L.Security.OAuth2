using System;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Caching {
	internal sealed partial class NullCache : ICache {

		private static readonly CacheResponse NULL_RESPONSE = new CacheResponse( success: false, value: null );

		[GenerateSync]
		Task<CacheResponse> ICache.GetAsync( string key ) {
			return Task.FromResult( NULL_RESPONSE );
		}

		[GenerateSync]
		Task ICache.SetAsync( string key, string value, TimeSpan expiry ) {
			return Task.CompletedTask;
		}

		[GenerateSync]
		Task ICache.RemoveAsync( string key ) {
			return Task.CompletedTask;
		}
	}
}
