namespace D2L.Security.OAuth2.Keys.Local {
	public interface IKeyManager : IPublicKeyProvider {
		IJsonWebTokenSigner CreateJsonWebTokenSigner( string issuer );
	}
}
