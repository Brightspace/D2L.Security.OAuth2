using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Caching {
	public class CacheResponse {

		private readonly bool m_success;
		private readonly string m_value;

		public CacheResponse( bool success, string value ) {
			m_success = success;
			m_value = value;
		}

		public bool Success {
			get { return m_success; }
		}

		public string Value {
			get { return m_value; }
		}

	}
}
