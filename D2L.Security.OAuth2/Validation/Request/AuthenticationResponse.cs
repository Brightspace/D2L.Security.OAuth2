using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Principal;

namespace D2L.Security.OAuth2.Validation.Request {
	public class AuthenticationResponse {

		private readonly AuthenticationStatus m_status;
		private readonly ID2LPrincipal m_principal;

		public AuthenticationResponse(
			AuthenticationStatus status,
			ID2LPrincipal principal
		) {
			m_status = status;
			m_principal = principal;
		}

		public AuthenticationStatus Status {
			get { return m_status; }
		}
		
		public ID2LPrincipal Principal {
			get { return m_principal; }
		}

	}
}
