using System.Web;

namespace D2L.Security.AuthTokenValidation {

	public interface IAuthTokenValidator {

		IGenericPrincipal VerifyAndDecode( HttpRequest request );
		IGenericPrincipal VerifyAndDecode( string jwt );
	}
}
