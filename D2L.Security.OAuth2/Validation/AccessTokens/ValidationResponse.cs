namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public class ValidationResponse {

		private readonly ValidationStatus m_status;
		private readonly IValidatedToken m_token;

		internal ValidationResponse(
			ValidationStatus status,
			IValidatedToken token
		) {
			m_status = status;
			m_token = token;
		}

		public ValidationStatus Status {
			get { return m_status; }
		}

		public IValidatedToken Token {
			get { return m_token; }
		}

	}
}
