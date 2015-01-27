using System.Web;

namespace D2L.Security.AuthTokenValidation {

	public interface IAuthTokenValidator {

		ValidationResult VerifyAndDecode( string jwt, out IGenericPrincipal principal );
	}
}
