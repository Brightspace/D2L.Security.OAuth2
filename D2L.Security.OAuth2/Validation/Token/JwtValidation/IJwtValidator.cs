namespace D2L.Security.OAuth2.Validation.Token.JwtValidation {
	
	/// <summary>
	/// Entry point into validating a jwt
	/// </summary>
	interface IJwtValidator {
		IValidatedToken Validate( string jwt );
	}
}
