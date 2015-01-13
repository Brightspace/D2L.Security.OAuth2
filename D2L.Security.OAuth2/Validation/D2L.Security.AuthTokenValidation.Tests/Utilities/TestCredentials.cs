namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	
	internal static class TestCredentials {
		
		internal static class LOReSScopes {
			internal static readonly string MANAGE = "https://api.brightspace.com/auth/lores.manage";
		}

		internal static class LOReSManager {
			internal static readonly string CLIENT_ID = "lores_manager_client";
			internal static readonly string SECRET = "lores_manager_secret";
		}
	}
}
