using System;

namespace D2L.Security.AuthTokenProvisioning.Client {
	internal sealed class AccessToken : IAccessToken {

		private readonly string m_token;
		private readonly TimeSpan m_expiresIn;

		internal AccessToken( string token, long expiresIn ) {
			m_token = token;
			m_expiresIn = TimeSpan.FromSeconds( expiresIn );
		}

		string IAccessToken.Token {
			get { return m_token; }
		}

		TimeSpan IAccessToken.ExpiresIn {
			get { return m_expiresIn; }
		}
	}
}
