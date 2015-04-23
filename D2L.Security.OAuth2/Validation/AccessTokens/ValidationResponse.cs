namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal sealed class ValidationResponse : IValidationResponse {

		private readonly ValidationStatus m_status;
		private readonly IAccessToken m_accessToken;

		internal ValidationResponse(
			ValidationStatus status,
			IAccessToken accessToken
		) {
			m_status = status;
			m_accessToken = accessToken;
		}

		ValidationStatus IValidationResponse.Status {
			get { return m_status; }
		}

		IAccessToken IValidationResponse.AccessToken {
			get { return m_accessToken; }
		}

	}
}
