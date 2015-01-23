namespace D2L.Security.RequestAuthentication {
	public enum AuthenticationResult {
		Success,
		Expired,
		TokenLocationConflict,
		Anonymous,
		BadXsrf
	}
}
