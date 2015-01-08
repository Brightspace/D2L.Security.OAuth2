namespace D2L.Security.AuthTokenValidation {
	public interface IAuthTokenCheckerFactory {
		IAuthTokenChecker Create();
	}
}
