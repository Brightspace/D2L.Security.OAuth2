using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Claims;

namespace D2L.Security.OAuth2.Keys.Local {
	public sealed class UnsignedToken {
		private readonly string m_audience;
		private readonly ReadOnlyCollection<Claim> m_claims;
		private readonly DateTime m_notBefore;
		private readonly DateTime m_expiresAt;

		public UnsignedToken(
			string audience,
			IList<Claim> claims,
			DateTime notBefore,
			DateTime expiresAt
		) {
			m_audience = audience;
			m_claims = new ReadOnlyCollection<Claim>( claims );
			m_notBefore = notBefore;
			m_expiresAt = expiresAt;
		}

		public string Audience {
			get { return m_audience; }
		}

		public ReadOnlyCollection<Claim> Claims {
			get { return m_claims; }
		}

		public DateTime NotBefore {
			get { return m_notBefore; }
		}

		public DateTime ExpiresAt {
			get { return m_expiresAt; }
		}
	}
}
