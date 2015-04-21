namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public class ValidationResponse {

		private readonly ValidationStatus m_status;
		private readonly IAccessToken m_accessToken;

		internal ValidationResponse(
			ValidationStatus status,
			IAccessToken accessToken
		) {
			m_status = status;
			m_accessToken = accessToken;
		}

		public ValidationStatus Status {
			get { return m_status; }
		}

		public IAccessToken AccessToken {
			get { return m_accessToken; }
		}

	}
}
