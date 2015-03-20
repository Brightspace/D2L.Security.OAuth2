using System.IdentityModel.Tokens;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	
	/// <summary>
	/// Used to decrypt tokens
	/// </summary>
	interface IPublicKey {
		SecurityKey SecurityKey { get; }
		string Issuer { get; }
	}
}
