using System.Web;

namespace D2L.Security.AuthTokenValidation {

	public interface IAuthTokenValidator {

		Principal VerifyAndDecode( HttpRequest request );
		Principal VerifyAndDecode( string jwt );
	}
}
