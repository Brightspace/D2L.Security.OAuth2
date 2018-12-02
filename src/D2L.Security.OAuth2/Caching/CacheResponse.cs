namespace D2L.Security.OAuth2.Caching {

	/// <summary>
	/// Holds a response from a cache get request
	/// </summary>
	public class CacheResponse {

		private readonly bool m_success;
		private readonly string m_value;

		/// <summary>
		/// Constructs a new <see cref="CacheResponse"/>
		/// </summary>
		/// <param name="success">Indicates if the value was successfully retrieved</param>
		/// <param name="value">The value that was retrieved</param>
		public CacheResponse( bool success, string value ) {
			m_success = success;
			m_value = value;
		}

		/// <summary>
		/// Indicates if the value was successfully retrieved
		/// </summary>
		public bool Success {
			get { return m_success; }
		}

		/// <summary>
		/// The value that was retrieved
		/// </summary>
		public string Value {
			get { return m_value; }
		}
	}
}
