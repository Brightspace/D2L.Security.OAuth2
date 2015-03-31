using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation {
	public interface IAccessTokenValidator {

		Task<ValidationResponse> ValidateAsync(
			Uri jwksEndPoint,
			string accessToken
		);

	}
}
