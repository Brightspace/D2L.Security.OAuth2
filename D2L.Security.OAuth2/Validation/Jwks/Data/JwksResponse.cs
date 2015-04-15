using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Jwks.Data {
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
