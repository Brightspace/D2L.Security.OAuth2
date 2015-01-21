using System.Web;

namespace D2L.Security.AuthTokenValidation {

	public interface IAuthTokenValidator {

		/// <summary>
		/// Verify and decode a token extracted from a request
		/// 
		/// Throws D2L.Security.AuthTokenValidation.TokenExpiredException if the token is expired.
		/// Throws D2L.Security.AuthTokenValidation.AuthorizationException if the validation failed for all other reasons
		/// </summary>
		/// <param name="request">The request whose token to validate and decode</param>
		/// <returns>A container of properties</returns>
		IGenericPrincipal VerifyAndDecode( HttpRequest request );
		
		/// <summary>
		/// Verify and decode a token
		/// 
		/// Throws D2L.Security.AuthTokenValidation.TokenExpiredException if the token is expired.
		/// Throws D2L.Security.AuthTokenValidation.AuthorizationException if the validation failed for all other reasons
		/// </summary>
		/// <param name="jwt">The jwt to validate and decode</param>
		/// <returns>A container of properties</returns>
		IGenericPrincipal VerifyAndDecode( string jwt );
	}
}
