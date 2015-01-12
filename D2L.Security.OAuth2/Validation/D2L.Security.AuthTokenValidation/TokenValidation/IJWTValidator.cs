namespace D2L.Security.AuthTokenValidation.TokenValidation {
	
	/// <summary>
	/// Entry point into validating a JWT
	/// </summary>
	interface IJWTValidator {
		IClaimsPrincipal Validate( string jwt );
	}
}
