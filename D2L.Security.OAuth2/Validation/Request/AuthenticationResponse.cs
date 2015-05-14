using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Validation.Request {

	/// <summary>
	/// Contains the status and principal of an authentication attempt
	/// </summary>
	public class AuthenticationResponse {

		private readonly AuthenticationStatus m_status;
		private readonly ID2LPrincipal m_principal;

		/// <summary>
		/// Constructs a new <see cref="AuthenticationResponse"/>
		/// </summary>
		/// <param name="status">Indicates the success or failure of the authentication attempt</param>
		/// <param name="principal">The principal object associated with the authentication attempt</param>
		public AuthenticationResponse(
			AuthenticationStatus status,
			ID2LPrincipal principal
		) {
			m_status = status;
			m_principal = principal;
		}

		/// <summary>
		/// Indicates the success or failure of the authentication attempt
		/// </summary>
		public AuthenticationStatus Status {
			get { return m_status; }
		}
		
		/// <summary>
		/// The principal object associated with the authentication attempt
		/// </summary>
		public ID2LPrincipal Principal {
			get { return m_principal; }
		}

	}
}
