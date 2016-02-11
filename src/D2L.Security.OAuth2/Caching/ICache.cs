using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Caching {

	/// <summary>
	/// A generic (string-value-based) caching interface
	/// </summary>
	public interface ICache {

		/// <summary>
		/// Attempts to retrieve the value for <paramref name="key"/> from the cache
		/// </summary>
		/// <param name="key">The key of the value to retrieve</param>
		/// <returns>For a cache hit, the value in the cache matching <paramref name="key"/>; for a cache miss, a <see cref="CacheResponse"/> with <see cref="CacheResponse.Success"/> set to false</returns>
		Task<CacheResponse> GetAsync(
			string key
		);

		/// <summary>
		/// Sets a value in the cache
		/// </summary>
		/// <param name="key">The key of the <paramref name="value"/> to cache</param>
		/// <param name="value">The value to cache</param>
		/// <param name="expiry">The maximum time the value can live in the cache for</param>
		Task SetAsync(
			string key,
			string value,
			TimeSpan expiry
		);

		/// <summary>
		/// Remove the item matching <paramref name="key"/> from the cache
		/// </summary>
		/// <param name="key">The key of the item to remove</param>
		Task RemoveAsync(
			string key
		);
	}
}
