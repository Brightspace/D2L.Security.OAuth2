namespace D2L.Security.OAuth2.Keys.Remote.Data {
	internal class JwksResponse {

		private readonly bool m_fromCache;
		private readonly string m_jwksJson;

		public JwksResponse(
			bool fromCache,
			string jwksJson
		) {
			m_fromCache = fromCache;
			m_jwksJson = jwksJson;
		}

		public string JwksJson {
			get { return m_jwksJson; }
		}

		public bool FromCache {
			get { return m_fromCache; }
		}
	}
}
