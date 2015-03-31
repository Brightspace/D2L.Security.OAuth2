using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Jwks.Data {
	public class JwkDto {

		private readonly string m_kty;
		private readonly string m_use;
		private readonly string m_kid;
		private readonly string m_e;
		private readonly string m_n;

		public JwkDto(
			string kty,
			string use,
			string kid,
			string e,
			string n
		) {
			m_kty = kty;
			m_use = use;
			m_kid = kid;
			m_e = e;
			m_n = n;
		}

		public string Kty {
			get { return m_kty; }
		}

		public string Use {
			get { return m_use; }
		}

		public string Kid {
			get { return m_kid; }
		}

		public string E {
			get { return m_e; }
		}

		public string N {
			get { return m_n; }
		}
	}
}
