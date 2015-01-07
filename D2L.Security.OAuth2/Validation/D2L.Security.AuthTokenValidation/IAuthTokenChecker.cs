using System.Web;

namespace D2L.Security.AuthTokenValidation {

	public interface IAuthTokenChecker {

		Principal VerifyAndDecode( HttpRequest request );
		Principal VerifyAndDecode( string jwt );
	}
}
