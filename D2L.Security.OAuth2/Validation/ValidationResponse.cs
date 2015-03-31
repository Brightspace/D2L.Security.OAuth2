using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Request.Core.Default;
using D2L.Security.OAuth2.Validation.Token;

namespace D2L.Security.OAuth2.Validation {
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
