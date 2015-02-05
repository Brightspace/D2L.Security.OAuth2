namespace D2L.Security.BrowserAuthTokens {

	/// <summary>
	/// Meant to be implemented by consumers to handle signing of 
	/// assertion grant token requests
	/// </summary>
	public interface IAssertionGrantSigner {
		string Sign( string token );
	}
}
