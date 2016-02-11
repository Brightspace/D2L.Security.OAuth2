namespace D2L.Security.OAuth2.Provisioning.Default {
	internal sealed class AccessToken : IAccessToken {

		private readonly string m_token;

		internal AccessToken( string token ) {
			m_token = token;
		}

		string IAccessToken.Token {
			get { return m_token; }
		}
	}
}
