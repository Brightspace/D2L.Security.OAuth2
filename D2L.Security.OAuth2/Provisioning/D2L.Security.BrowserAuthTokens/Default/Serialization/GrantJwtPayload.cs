using System;
using System.Runtime.Serialization;

namespace D2L.Security.BrowserAuthTokens.Default.Serialization {
	[DataContract]
	internal sealed class GrantJwtPayload {

		private readonly long m_expiry;
		private readonly string m_userId;
		private readonly string m_tenantId;
		private readonly string m_tenantUrl;

		internal GrantJwtPayload(
			string userId,
			string tenantId,
			string tenantUrl
			) {

			m_userId = userId;
			m_tenantId = tenantId;
			m_tenantUrl = tenantUrl;

			DateTime expiry = DateTime.UtcNow + TimeSpan.FromMinutes( 30 );
			m_expiry = expiry.GetSecondsSinceUnixEpoch();
		}

		[DataMember]
		public string iss {
			get { return "lms.dev.d2l"; }
			private set { }
		}

		[DataMember]
		public string sub {
			get { return m_userId; }
			set { }
		}

		[DataMember]
		public long exp {
			get { return m_expiry; }
			set { }
		}
		
		[DataMember]
		public string aud {
			get { return "https://api.brightspace.com/auth/token"; }
			private set { }
		}

		[DataMember]
		public string tenantid {
			get { return m_tenantId; }
			set { }
		}

		[DataMember]
		public string tenanturl {
			get { return m_tenantUrl; }
			set { }
		}
	}
}
