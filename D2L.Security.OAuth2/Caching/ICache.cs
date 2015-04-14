using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Caching {

	public interface ICache {

		Task<CacheResponse> GetAsync(
			string key
		);

		Task SetAsync(
			string key,
			string value,
			TimeSpan expiry
		);

		Task RemoveAsync(
			string key
		);
	}
}
