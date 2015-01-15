using System.IdentityModel.Tokens;

namespace D2L.Security.AuthTokenValidation.TokenValidation.Default {
	internal static class Helper {
		
		internal static TokenValidationParameters CreateValidationParameters( 
			string issuer,
			SecurityKey issuerKey
			) {

			TokenValidationParameters parameters = new TokenValidationParameters();
			parameters.ValidIssuer = issuer;
			parameters.IssuerSigningKey = issuerKey;
			parameters.ValidateLifetime = true;
			parameters.ValidateIssuerSigningKey = true;
			parameters.ValidateIssuer = true;

			parameters.ValidateAudience = false;
			parameters.ValidateActor = false;

			return parameters;
		}
	}
}
