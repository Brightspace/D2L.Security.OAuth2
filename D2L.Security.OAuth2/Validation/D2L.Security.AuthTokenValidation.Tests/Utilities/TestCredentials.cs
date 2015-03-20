namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	
	internal static class TestCredentials {
		
		internal static class LOReSScopes {
			internal const string MANAGE = "https://api.brightspace.com/auth/lores.manage";
		}

		internal static class LOReSManager {
			internal const string CLIENT_ID = "lores_manager_client";
			internal const string SECRET = "lores_manager_secret";
		}
	}
}
