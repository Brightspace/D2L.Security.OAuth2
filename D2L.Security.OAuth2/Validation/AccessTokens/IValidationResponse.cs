using System;
using System.Collections.Generic;
using System.Linq;
namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public interface IValidationResponse {
		ValidationStatus Status { get; }
		IAccessToken AccessToken { get; }
	}
}
