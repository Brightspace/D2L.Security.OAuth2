namespace D2L.Security.AuthTokenValidation.TokenValidation {
	
	interface IJWTValidator {
		bool TryValidate( string jwt, out IClaimsPrincipal claimsPrincipal );
	}
}
