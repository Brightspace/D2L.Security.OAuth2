namespace D2L.Security.RequestAuthentication.Tests.Utilities {
	
	internal static class TestTokens {

		internal static class ValidWithXsrfOneScope {
			internal const string Sub = "169";
			internal const string Tenantid = "tenant-0000-0000-0000-000000000000";
			internal const string Tenanturl = "http://lores.d2l";
			internal const string Xt = "abc";
			internal const long Exp = 1621858476;
			internal const string Iss = "https://api.brightspace.com/auth";
			internal const string Scope = "https://api.brightspace.com/auth/lores.manage";

			internal const string Jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxNjkiLCJ0ZW5hbnR1cmwiOiJodHRwOi8vbG9yZXMuZDJsIiwidGVuYW50aWQiOiJ0ZW5hbnQtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwieHQiOiJhYmMiLCJleHAiOjE2MjE4NTg0NzYsImlzcyI6Imh0dHBzOi8vYXBpLmJyaWdodHNwYWNlLmNvbS9hdXRoIiwic2NvcGUiOiJodHRwczovL2FwaS5icmlnaHRzcGFjZS5jb20vYXV0aC9sb3Jlcy5tYW5hZ2UifQ.hN23bTewSSKIb1muiSgdxGFNeYabNBsWijjv7G_GT7cRK16aB_dftAcmyqONH1T4GJ9idlygLEJdFC5khjB_zvh-SxDx-kIGsENrXozpsG_eJWwI_u1xG6JTLWWZ6ESC4rgYdQ5TJo-QKLp0V2NEtwLfNqNa7YZtt0yGTo0CPKGHTQAonjsq8qSqrfBQBX87bYGMQVZo2Ki0Lh_UTY3LB71LbEmfc89xOQP2GxrMM_6hzxRVGEZ4V7odfoNoM8qy_IvzRGTRHGBWjGYvD1Ukr7XyBbwaHfzaYbOE4eXfnwGDV2WK5WPPB-s0pWqeebLaA44H9Fnvtd740-CYsUZFUQ";
		}

		internal static class ValidWithXsrfTwoScopesNoUser {
			internal const string Tenantid = "tenant-0000-0000-0000-000000000000";
			internal const string Tenanturl = "http://lores.d2l";
			internal const string Xt = "abc";
			internal const long Exp = 1621858476;
			internal const string Iss = "https://api.brightspace.com/auth";
			internal const string Scope1 = "https://api.brightspace.com/auth/lores.manage";
			internal const string Scope2 = "https://api.brightspace.com/auth/lores.read";

			internal const string Jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnR1cmwiOiJodHRwOi8vbG9yZXMuZDJsIiwidGVuYW50aWQiOiJ0ZW5hbnQtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwieHQiOiJhYmMiLCJleHAiOjE2MjE4NTg0NzYsImlzcyI6Imh0dHBzOi8vYXBpLmJyaWdodHNwYWNlLmNvbS9hdXRoIiwic2NvcGUiOiJodHRwczovL2FwaS5icmlnaHRzcGFjZS5jb20vYXV0aC9sb3Jlcy5tYW5hZ2UgaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMucmVhZCJ9.S65Ja0A0aiE-LQvZvNJGPZTmya79suuWQU3uXuPEY_FXBRaw29cdGVZ7SLcZ1fnYfnmX5Pqh2CoHa_W44_2ICigph2u_TfFplLECzgB5L61nsH4L9xeiQ67g57NHVIMUNi7WbK-vC3bKSzZrBzY3XrI5j8_KX_XbdCn-tDhw7GwRPAMvVzXaDNEXKby4HBf48WZyapbrTLQy4evNUdz5WgyIkFniqJHqCSVzxC6eiEMZov-nFGT40L3VK0y4k4NyLncc5jPeZ0LF7SNG_2F6ye7lFyQCNjJWbbmc-8OHbC-yv036inNYj05AwmkLrzmzJU4L6mlYoFY60-JHtPceBA";
		}

		internal static class ValidNoXsrfOneScope {
			internal const string Sub = "169";
			internal const string Tenantid = "tenant-0000-0000-0000-000000000000";
			internal const string Tenanturl = "http://lores.d2l";
			internal const long Exp = 1621858476;
			internal const string Iss = "https://api.brightspace.com/auth";
			internal const string Scope = "https://api.brightspace.com/auth/lores.manage";

			internal const string Jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjE2OSwidGVuYW50dXJsIjoiaHR0cDovL2xvcmVzLmQybCIsInRlbmFudGlkIjoidGVuYW50LTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsImV4cCI6MTYyMTg1ODQ3NiwiaXNzIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgiLCJzY29wZSI6Imh0dHBzOi8vYXBpLmJyaWdodHNwYWNlLmNvbS9hdXRoL2xvcmVzLm1hbmFnZSJ9.ikB-C7x47nmgQeZt3MPTL0vVyG--rECTp1BjwBSg3ebwzhXD1Gq_85bcHMyhZZMZzENyZVDJITL0r5FT5g9xle_sqOxjitJwHTT9-40r--pp30-pgbDA5_IEbv6iI2rSEZuhwKuzM4SuNCyc3MeOs-fi-BouO6w_MR0ZN0q90Ni5gZ_sOGn_Yr5lYoSjtMpg6tOu1zYkkKUfaCLnNdCRSSV-hYOjamzkPlgvq-kc9KCRCxPWEDgzbryDL0oTW25sJep5moNlX9MgxQ8ZkegaeWHXSQT-tyrVsmK0jKRBSrHk3qEZs3-DrigKrZ2DIpvEDf9-CBBHoIn6qzgh1OQGYg";
		}
	}
}
