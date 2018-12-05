using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Caching {

	/// <summary>
	/// Holds a response from a cache get request
	/// </summary>
	[Immutable]
	public class CacheResponse {

		/// <summary>
		/// Constructs a new <see cref="CacheResponse"/>
		/// </summary>
		/// <param name="success">Indicates if the value was successfully retrieved</param>
		/// <param name="value">The value that was retrieved</param>
		public CacheResponse( bool success, string value ) {
			Success = success;
			Value = value;
		}

		/// <summary>
		/// Indicates if the value was successfully retrieved
		/// </summary>
		public bool Success { get; }

		/// <summary>
		/// The value that was retrieved
		/// </summary>
		public string Value { get; }
	}
}
