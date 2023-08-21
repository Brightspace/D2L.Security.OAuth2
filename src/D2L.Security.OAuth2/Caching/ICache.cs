using System;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Caching {

	/// <summary>
	/// A generic (string-value-based) caching interface
	/// </summary>
	public partial interface ICache {

		/// <summary>
		/// Attempts to retrieve the value for <paramref name="key"/> from the cache
		/// </summary>
		/// <param name="key">The key of the value to retrieve</param>
		/// <returns>For a cache hit, the value in the cache matching <paramref name="key"/>; for a cache miss, a <see cref="CacheResponse"/> with <see cref="CacheResponse.Success"/> set to false</returns>
		[GenerateSync]
		Task<CacheResponse> GetAsync(
			string key
		);

		/// <summary>
		/// Sets a value in the cache
		/// </summary>
		/// <param name="key">The key of the <paramref name="value"/> to cache</param>
		/// <param name="value">The value to cache</param>
		/// <param name="expiry">The maximum time the value can live in the cache for</param>
		[GenerateSync]
		Task SetAsync(
			string key,
			string value,
			TimeSpan expiry
		);

		/// <summary>
		/// Remove the item matching <paramref name="key"/> from the cache
		/// </summary>
		/// <param name="key">The key of the item to remove</param>
		[GenerateSync]
		Task RemoveAsync(
			string key
		);
	}
}
