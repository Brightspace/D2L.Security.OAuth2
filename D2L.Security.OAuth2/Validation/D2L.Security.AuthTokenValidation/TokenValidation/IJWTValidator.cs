namespace D2L.Security.AuthTokenValidation.TokenValidation {
	
	/// <summary>
	/// Entry point into validating a JWT
	/// </summary>
	interface IJWTValidator {

		/// <summary>
		/// Does not throw exceptions.
		/// </summary>
		/// <param name="jwt">The JWT to validate</param>
		/// <param name="claimsPrincipal">The result of a successful validation</param>
		/// <returns>True if the validation was successful, and False otherwise</returns>
		bool TryValidate( string jwt, out IClaimsPrincipal claimsPrincipal );
	}
}
