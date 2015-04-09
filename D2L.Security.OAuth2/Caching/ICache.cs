using System;

namespace D2L.Security.OAuth2.Caching {

	// TODO async?
	public interface ICache {

		bool TryGet(
			string key,
			out string value
		);

		void Set(
			string key,
			string value,
			TimeSpan expiry
		);

		void Remove(
			string key
		);
	}
}
