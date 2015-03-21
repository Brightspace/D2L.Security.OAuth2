using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Validation.Token.PublicKeys {
	
	/// <summary>
	/// Used to decrypt tokens
	/// </summary>
	interface IPublicKey {
		SecurityKey SecurityKey { get; }
		string Issuer { get; }
	}
}
